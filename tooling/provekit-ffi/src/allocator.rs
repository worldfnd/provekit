//! Custom allocator that forwards to host-provided allocation functions (via C
//! ABI).

use std::alloc::{GlobalAlloc, Layout};

// External C functions that must be provided by the embedding application.
// These are linked at compile time and used as the global allocator.
// The host application can implement these functions to use custom memory
// management strategies (e.g., memory pools, mmap, device-specific allocators).
extern "C" {
    /// Host-provided allocation function used for Rust heap allocations.
    ///
    /// # Parameters
    /// * `size` - Number of bytes to allocate
    /// * `align` - Required alignment for the allocation
    ///
    /// # Returns
    /// Pointer to allocated memory, or null on failure
    fn provekit_alloc(size: usize, align: usize) -> *mut u8;

    /// Host-provided deallocation function used for Rust heap deallocations.
    ///
    /// # Parameters
    /// * `ptr` - Pointer to memory previously allocated by provekit_alloc
    fn provekit_free(ptr: *mut u8);
}

struct ProveKitAllocator;

unsafe impl GlobalAlloc for ProveKitAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        provekit_alloc(size, align)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        provekit_free(ptr);
    }
}

// Global allocator instance
#[global_allocator]
static ALLOCATOR: ProveKitAllocator = ProveKitAllocator;
