use std::{
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{AtomicUsize, Ordering},
};
#[cfg(feature = "tracy")]
use {std::sync::atomic::AtomicBool, tracing_tracy::client::sys as tracy_sys};

/// Minimum allocation size (bytes) to trigger prefault. Smaller allocations skip madvise.
const PREFAULT_THRESHOLD: usize = 128 * 1024;

/// Pre-fault and optionally advise the kernel for large allocations on Linux.
/// Reduces concurrent anonymous page faults when many threads touch new memory.
/// `ptr` must be a valid allocation of at least `size` bytes.
#[cfg(target_os = "linux")]
unsafe fn prefault(ptr: *mut u8, size: usize) {
    if size < PREFAULT_THRESHOLD || ptr.is_null() {
        return;
    }

    let page = {
        static PAGE_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *PAGE_SIZE.get_or_init(|| {
            let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            usize::try_from(p).ok().filter(|v| *v > 0).unwrap_or(4096)
        })
    };
    let mask = page - 1; // page is always a power of two on Linux

    let start = ptr as usize;
    let end = match start.checked_add(size) {
        Some(e) => e,
        None => return,
    };

    // Round start up and end down so we only touch pages fully inside [ptr, ptr+size).
    let safe_start = match start.checked_add(mask) {
        Some(s) => s & !mask,
        None => return,
    };
    let safe_end = end & !mask;

    if safe_start >= safe_end {
        return;
    }

    let aligned_ptr = safe_start as *mut libc::c_void;
    let aligned_size = safe_end - safe_start;

    let _ = libc::madvise(aligned_ptr, aligned_size, libc::MADV_HUGEPAGE);
    let _ = libc::madvise(aligned_ptr, aligned_size, libc::MADV_POPULATE_WRITE);
}

#[cfg(not(target_os = "linux"))]
unsafe fn prefault(_ptr: *mut u8, _size: usize) {}

#[cfg(feature = "jemalloc")]
static BACKING: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
#[cfg(all(not(feature = "jemalloc"), feature = "mimalloc"))]
static BACKING: mimalloc::MiMalloc = mimalloc::MiMalloc;
#[cfg(all(not(feature = "jemalloc"), not(feature = "mimalloc")))]
static BACKING: std::alloc::System = std::alloc::System;

/// Custom allocator that keeps track of statistics to see program memory
/// consumption.
pub struct ProfilingAllocator {
    /// Allocated bytes
    current: AtomicUsize,

    /// Maximum allocated bytes (reached so far)
    max: AtomicUsize,

    /// Number of allocations done
    count: AtomicUsize,

    /// Enable Tracy allocation profiling
    #[cfg(feature = "tracy")]
    tracy_enabled: AtomicBool,

    /// Stack depth to include in Tracy allocation profiling
    /// (only used if `tracy_enabled` is true)
    /// **Note.** This makes allocation very slow.
    #[cfg(feature = "tracy")]
    tracy_depth: AtomicUsize,
}

impl ProfilingAllocator {
    pub const fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            max:     AtomicUsize::new(0),
            count:   AtomicUsize::new(0),

            #[cfg(feature = "tracy")]
            tracy_enabled:                           AtomicBool::new(false),
            #[cfg(feature = "tracy")]
            tracy_depth:                             AtomicUsize::new(0),
        }
    }

    pub fn current(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }

    pub fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }

    pub fn reset_max(&self) -> usize {
        let current = self.current();
        self.max.store(current, Ordering::SeqCst);
        current
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    #[cfg(feature = "tracy")]
    pub fn enable_tracy(&self, depth: usize) {
        self.tracy_enabled.store(true, Ordering::SeqCst);
        self.tracy_depth.store(depth, Ordering::SeqCst);
    }

    #[allow(unused_variables)] // Conditional compilation may not use all variables
    fn tracy_alloc(&self, size: usize, ptr: *mut u8) {
        // If Tracy profiling is enabled, report this allocation to Tracy.
        #[cfg(feature = "tracy")]
        if self.tracy_enabled.load(Ordering::SeqCst) {
            let depth = self.tracy_depth.load(Ordering::SeqCst);
            if depth == 0 {
                // If depth is 0, we don't capture any stack information
                unsafe {
                    tracy_sys::___tracy_emit_memory_alloc(ptr.cast(), size, 1);
                }
            } else {
                // Capture stack information up to `depth` frames
                unsafe {
                    tracy_sys::___tracy_emit_memory_alloc_callstack(
                        ptr.cast(),
                        size,
                        depth as i32,
                        1,
                    );
                }
            }
        }
    }

    #[allow(unused_variables)] // Conditional compilation may not use all variables
    fn tracy_dealloc(&self, ptr: *mut u8) {
        // If Tracy profiling is enabled, report this deallocation to Tracy.
        #[cfg(feature = "tracy")]
        if self.tracy_enabled.load(Ordering::SeqCst) {
            let depth = self.tracy_depth.load(Ordering::SeqCst);
            if depth == 0 {
                // If depth is 0, we don't capture any stack information
                unsafe {
                    tracy_sys::___tracy_emit_memory_free(ptr.cast(), 1);
                }
            } else {
                // Capture stack information up to `depth` frames
                unsafe {
                    tracy_sys::___tracy_emit_memory_free_callstack(ptr.cast(), depth as i32, 1);
                }
            }
        }
    }
}

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for ProfilingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = BACKING.alloc(layout);
        let size = layout.size();
        let current = self
            .current
            .fetch_add(size, Ordering::SeqCst)
            .wrapping_add(size);
        self.max.fetch_max(current, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        self.tracy_alloc(size, ptr);
        prefault(ptr, size);
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.current.fetch_sub(layout.size(), Ordering::SeqCst);
        self.tracy_dealloc(ptr);
        BACKING.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = BACKING.alloc_zeroed(layout);
        let size = layout.size();
        let current = self
            .current
            .fetch_add(size, Ordering::SeqCst)
            .wrapping_add(size);
        self.max.fetch_max(current, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        self.tracy_alloc(size, ptr);
        prefault(ptr, size);
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        self.tracy_dealloc(ptr);
        let ptr = BACKING.realloc(ptr, old_layout, new_size);
        let old_size = old_layout.size();
        if new_size > old_size {
            let diff = new_size - old_size;
            let current = self
                .current
                .fetch_add(diff, Ordering::SeqCst)
                .wrapping_add(diff);
            self.max.fetch_max(current, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
        } else {
            self.current
                .fetch_sub(old_size - new_size, Ordering::SeqCst);
        }
        self.tracy_alloc(new_size, ptr);
        prefault(ptr, new_size);
        ptr
    }
}
