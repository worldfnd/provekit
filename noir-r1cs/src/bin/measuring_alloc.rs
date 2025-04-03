use std::{
    alloc::{GlobalAlloc, Layout, System as SystemAlloc},
    sync::atomic::{AtomicUsize, Ordering},
};

/// Custom allocator that keeps track of statistics to see program memory
/// consumption.
pub struct MeasuringAllocator {
    current: AtomicUsize,
    max:     AtomicUsize,
    count:   AtomicUsize,
}

impl MeasuringAllocator {
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
unsafe impl GlobalAlloc for MeasuringAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // We just ignore the race conditions here...
        let prev = self.current.fetch_add(layout.size(), Ordering::SeqCst);
        self.max.fetch_max(prev + layout.size(), Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        SystemAlloc.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.current.fetch_sub(layout.size(), Ordering::SeqCst);
        SystemAlloc.dealloc(ptr, layout)
    }
}
