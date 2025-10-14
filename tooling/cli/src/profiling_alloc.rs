use std::{
    alloc::{GlobalAlloc, Layout, System as SystemAlloc},
    sync::atomic::{AtomicUsize, Ordering},
};
#[cfg(feature = "tracy")]
use {std::sync::atomic::AtomicBool, tracing_tracy::client::sys as tracy_sys};

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

    #[cfg(feature = "tracy")]
    pub fn disable_tracy(&self) {
        self.tracy_enabled.store(false, Ordering::SeqCst);
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
        let ptr = SystemAlloc.alloc(layout);
        let size = layout.size();
        let current = self
            .current
            .fetch_add(size, Ordering::SeqCst)
            .wrapping_add(size);
        self.max.fetch_max(current, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        self.tracy_alloc(size, ptr);
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.current.fetch_sub(layout.size(), Ordering::SeqCst);
        self.tracy_dealloc(ptr);
        SystemAlloc.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = SystemAlloc.alloc_zeroed(layout);
        let size = layout.size();
        let current = self
            .current
            .fetch_add(size, Ordering::SeqCst)
            .wrapping_add(size);
        self.max.fetch_max(current, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        self.tracy_alloc(size, ptr);
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let ptr = SystemAlloc.realloc(ptr, old_layout, new_size);
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
        ptr
    }
}
