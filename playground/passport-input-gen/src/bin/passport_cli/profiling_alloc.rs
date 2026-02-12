use std::{
    alloc::{GlobalAlloc, Layout, System as SystemAlloc},
    sync::atomic::{AtomicUsize, Ordering},
};

/// Custom allocator that keeps track of statistics to see program memory
/// consumption.
pub struct ProfilingAllocator {
    /// Allocated bytes
    current: AtomicUsize,

    /// Maximum allocated bytes (reached so far)
    max: AtomicUsize,

    /// Number of allocations done
    count: AtomicUsize,
}

impl ProfilingAllocator {
    pub const fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            max:     AtomicUsize::new(0),
            count:   AtomicUsize::new(0),
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
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.current.fetch_sub(layout.size(), Ordering::SeqCst);
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
        ptr
    }
}
