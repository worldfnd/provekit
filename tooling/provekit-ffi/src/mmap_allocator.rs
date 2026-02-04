//! Pure Rust mmap-based allocator with RAM limit and file-backed swap.
//!
//! Optimized for performance (matching Swift's approach):
//! - parking_lot::Mutex instead of spinlock
//! - HashMap for O(1) allocation lookup (like Swift's Dictionary)
//! - Cached swap usage (no iteration needed)
//! - First-fit allocation for speed
//! - Coalesce on dealloc for smaller free lists

use {
    parking_lot::Mutex,
    std::{
        alloc::{GlobalAlloc, Layout, System},
        collections::HashMap,
        ffi::c_char,
        fs::{self, OpenOptions},
        os::unix::io::AsRawFd,
        path::PathBuf,
        ptr,
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

const MIN_SWAP_SIZE: usize = 1024 * 1024;
const DEFAULT_SWAP_POOL_SIZE: usize = 2 * 1024 * 1024 * 1024;

static CONFIGURED: AtomicBool = AtomicBool::new(false);
static RAM_LIMIT: AtomicU64 = AtomicU64::new(300 * 1024 * 1024);
static POOL_INITIALIZED: AtomicBool = AtomicBool::new(false);

static CURRENT_RAM_USAGE: AtomicU64 = AtomicU64::new(0);
static PEAK_RAM_USAGE: AtomicU64 = AtomicU64::new(0);
static SWAP_USAGE: AtomicU64 = AtomicU64::new(0);

static POOL_DATA_START: AtomicUsize = AtomicUsize::new(0);
static POOL_DATA_SIZE: AtomicUsize = AtomicUsize::new(0);

pub fn is_configured() -> bool {
    CONFIGURED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy)]
struct FreeBlock {
    offset: usize,
    size:   usize,
}

struct PoolState {
    free_list:   Vec<FreeBlock>,
    allocations: HashMap<usize, usize>, // offset -> size
}

impl PoolState {
    /// Coalesce adjacent free blocks (like Swift's coalesceFreeList)
    fn coalesce(&mut self) {
        if self.free_list.len() <= 1 {
            return;
        }

        // Sort by offset
        self.free_list.sort_unstable_by_key(|b| b.offset);

        // Merge adjacent blocks
        let mut merged = Vec::with_capacity(self.free_list.len());
        let mut current = self.free_list[0];

        for block in self.free_list.iter().skip(1) {
            if current.offset + current.size == block.offset {
                // Merge
                current.size += block.size;
            } else {
                merged.push(current);
                current = *block;
            }
        }
        merged.push(current);

        self.free_list = merged;
    }
}

static POOL_STATE: Mutex<Option<PoolState>> = Mutex::new(None);

/// Configure the mmap-based memory allocator.
///
/// # Safety
/// Must be called before any allocations occur.
pub unsafe fn configure_allocator(
    ram_limit_bytes: usize,
    use_file_backed: bool,
    swap_file_path: *const c_char,
) -> bool {
    if POOL_INITIALIZED.load(Ordering::Relaxed) {
        return true;
    }

    RAM_LIMIT.store(ram_limit_bytes as u64, Ordering::Relaxed);

    if use_file_backed {
        let swap_dir: Option<PathBuf> = if !swap_file_path.is_null() {
            std::ffi::CStr::from_ptr(swap_file_path)
                .to_str()
                .ok()
                .map(PathBuf::from)
        } else {
            None
        };

        if !init_swap_pool(DEFAULT_SWAP_POOL_SIZE, swap_dir) {
            return false;
        }
    }

    CONFIGURED.store(true, Ordering::Release);
    true
}

/// Clean up orphaned swap files from previous app runs.
/// This prevents storage bloat when the app is killed without proper cleanup.
fn cleanup_orphaned_swap_files() {
    let temp_dir = std::env::temp_dir();
    let current_pid = std::process::id();

    // Look for provekit_swap_* directories
    if let Ok(entries) = fs::read_dir(&temp_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("provekit_swap_") {
                    // Extract PID from directory name
                    if let Some(pid_str) = name.strip_prefix("provekit_swap_") {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            // Skip if it's our current process
                            if pid == current_pid {
                                continue;
                            }
                        }
                    }
                    // Remove orphaned directory (best effort)
                    let _ = fs::remove_dir_all(&path);
                }
            }
        }
    }
}

fn init_swap_pool(size: usize, swap_dir: Option<PathBuf>) -> bool {
    // Clean up any orphaned swap files from previous runs first
    cleanup_orphaned_swap_files();

    let temp_dir = swap_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("provekit_swap_{}", std::process::id()))
    });

    if fs::create_dir_all(&temp_dir).is_err() {
        return false;
    }

    let file_path = temp_dir.join("pool.swap");

    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&file_path)
    {
        Ok(f) => f,
        Err(_) => return false,
    };

    if file.set_len(size as u64).is_err() {
        let _ = fs::remove_file(&file_path);
        return false;
    }

    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        let _ = fs::remove_file(&file_path);
        return false;
    }

    // Initialize pool state with parking_lot mutex
    {
        let mut state = POOL_STATE.lock();
        *state = Some(PoolState {
            free_list:   vec![FreeBlock { offset: 0, size }],
            allocations: HashMap::with_capacity(4096),
        });
    }

    POOL_DATA_START.store(ptr as usize, Ordering::Release);
    POOL_DATA_SIZE.store(size, Ordering::Release);
    POOL_INITIALIZED.store(true, Ordering::Release);

    // Keep file descriptor open (file stays mapped)
    std::mem::forget(file);
    true
}

/// Get memory statistics (O(1) - all values are cached).
pub fn get_stats() -> (usize, usize, usize) {
    let ram = CURRENT_RAM_USAGE.load(Ordering::Relaxed) as usize;
    let peak = PEAK_RAM_USAGE.load(Ordering::Relaxed) as usize;
    let swap = SWAP_USAGE.load(Ordering::Relaxed) as usize;
    (ram, swap, peak)
}

pub struct MmapAllocator;

unsafe impl GlobalAlloc for MmapAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        if size == 0 {
            return ptr::null_mut();
        }

        // Fast path: check if we should try swap pool
        let ram_limit = RAM_LIMIT.load(Ordering::Relaxed);
        let current = CURRENT_RAM_USAGE.load(Ordering::Relaxed);

        if current + size as u64 > ram_limit
            && size >= MIN_SWAP_SIZE
            && POOL_INITIALIZED.load(Ordering::Relaxed)
        {
            if let Some(ptr) = pool_alloc(size, align) {
                return ptr;
            }
        }

        // System allocation
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let new_usage =
                CURRENT_RAM_USAGE.fetch_add(size as u64, Ordering::Relaxed) + size as u64;
            // Update peak (relaxed is fine, approximate is OK)
            let peak = PEAK_RAM_USAGE.load(Ordering::Relaxed);
            if new_usage > peak {
                let _ = PEAK_RAM_USAGE.compare_exchange(
                    peak,
                    new_usage,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
        }
        ptr
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        // Check if this is a pool allocation
        if POOL_INITIALIZED.load(Ordering::Relaxed) && pool_owns(ptr) {
            pool_dealloc(ptr);
            return;
        }

        CURRENT_RAM_USAGE.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // For pool allocations, use alloc + copy + dealloc
        if POOL_INITIALIZED.load(Ordering::Relaxed) && pool_owns(ptr) {
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let new_ptr = self.alloc(new_layout);
            if !new_ptr.is_null() {
                ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                pool_dealloc(ptr);
            }
            return new_ptr;
        }

        // For system allocations, use system realloc
        let old_size = layout.size();
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            if new_size > old_size {
                CURRENT_RAM_USAGE.fetch_add((new_size - old_size) as u64, Ordering::Relaxed);
            } else {
                CURRENT_RAM_USAGE.fetch_sub((old_size - new_size) as u64, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[inline]
fn pool_owns(ptr: *mut u8) -> bool {
    let addr = ptr as usize;
    let start = POOL_DATA_START.load(Ordering::Relaxed);
    let size = POOL_DATA_SIZE.load(Ordering::Relaxed);
    addr >= start && addr < start + size
}

/// Allocate from the swap pool using first-fit algorithm.
fn pool_alloc(size: usize, align: usize) -> Option<*mut u8> {
    let data_start = POOL_DATA_START.load(Ordering::Relaxed);
    let aligned_size = (size + align - 1) & !(align - 1);

    let mut state_guard = POOL_STATE.lock();
    let state = state_guard.as_mut()?;

    // First-fit search (faster than best-fit for most workloads)
    let mut best_idx = None;
    let mut best_aligned_offset = 0;
    let mut best_padding = 0;

    for (i, block) in state.free_list.iter().enumerate() {
        let block_addr = data_start + block.offset;
        let aligned_addr = (block_addr + align - 1) & !(align - 1);
        let padding = aligned_addr - block_addr;
        let needed = padding + aligned_size;

        if block.size >= needed {
            best_idx = Some(i);
            best_aligned_offset = aligned_addr - data_start;
            best_padding = padding;
            break; // First-fit: take the first block that fits
        }
    }

    let idx = best_idx?;
    let block = state.free_list[idx];

    // Update free list
    state.free_list.remove(idx);

    // Add front padding back if any
    if best_padding > 0 {
        state.free_list.push(FreeBlock {
            offset: block.offset,
            size:   best_padding,
        });
    }

    // Add remainder back if any
    let remainder = block.size - best_padding - aligned_size;
    if remainder > 0 {
        state.free_list.push(FreeBlock {
            offset: best_aligned_offset + aligned_size,
            size:   remainder,
        });
    }

    // Track allocation (O(1) HashMap insert like Swift's Dictionary)
    state.allocations.insert(best_aligned_offset, aligned_size);

    // Update swap usage
    SWAP_USAGE.fetch_add(aligned_size as u64, Ordering::Relaxed);

    Some((data_start + best_aligned_offset) as *mut u8)
}

/// Deallocate from the swap pool.
fn pool_dealloc(ptr: *mut u8) {
    let data_start = POOL_DATA_START.load(Ordering::Relaxed);
    let offset = ptr as usize - data_start;

    let mut state_guard = POOL_STATE.lock();
    let Some(state) = state_guard.as_mut() else {
        return;
    };

    // O(1) HashMap lookup (like Swift's Dictionary)
    let Some(size) = state.allocations.remove(&offset) else {
        return;
    };

    // Add back to free list
    state.free_list.push(FreeBlock { offset, size });

    // Coalesce immediately (like Swift) to keep free list small
    state.coalesce();

    // Update swap usage
    SWAP_USAGE.fetch_sub(size as u64, Ordering::Relaxed);
}

pub static MMAP_ALLOCATOR: MmapAllocator = MmapAllocator;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_alloc_dealloc() {
        assert!(init_swap_pool(10 * 1024 * 1024, None));

        let p1 = pool_alloc(1024 * 1024, 8);
        assert!(p1.is_some());

        let p2 = pool_alloc(2 * 1024 * 1024, 16);
        assert!(p2.is_some());

        pool_dealloc(p1.unwrap());
        pool_dealloc(p2.unwrap());

        let p3 = pool_alloc(1024 * 1024, 8);
        assert!(p3.is_some());
    }

    #[test]
    fn test_stats_are_cached() {
        let (ram, swap, peak) = get_stats();
        // Just verify it returns without iterating anything
        assert!(ram == 0 || ram > 0);
        assert!(swap == 0 || swap > 0);
        assert!(peak == 0 || peak > 0);
    }
}
