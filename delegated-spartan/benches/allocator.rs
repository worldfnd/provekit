use {
    core::sync::atomic::{AtomicUsize, Ordering},
    std::alloc::{GlobalAlloc, System as SystemAllocator},
};

pub struct MeasuringAllocator<Inner: GlobalAlloc> {
    inner: Inner,
    count: AtomicUsize,
    total: AtomicUsize,
    max:   AtomicUsize,
}

impl<Inner: GlobalAlloc> MeasuringAllocator<Inner> {
    pub fn reset(&self) {
        self.max
            .store(self.total.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    pub fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }
}

unsafe impl<Inner: GlobalAlloc> GlobalAlloc for MeasuringAllocator<Inner> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let ptr = self.inner.alloc(layout);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(layout.size(), Ordering::SeqCst);
        self.max
            .fetch_max(self.total.load(Ordering::SeqCst), Ordering::SeqCst);
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        self.inner.dealloc(ptr, layout);
        self.total.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
pub static ALLOCATOR: MeasuringAllocator<SystemAllocator> = MeasuringAllocator {
    inner: SystemAllocator,
    count: AtomicUsize::new(0),
    total: AtomicUsize::new(0),
    max:   AtomicUsize::new(0),
};
