//! Callback-based allocator that delegates to host via FFI.
//!
//! SAFETY: pk_set_allocator must be called before any allocations occur.
//! This is guaranteed by calling it in Swift's init() before pk_init().

use std::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr,
};

type AllocFn = unsafe extern "C" fn(size: usize, align: usize) -> *mut c_void;
type DeallocFn = unsafe extern "C" fn(ptr: *mut c_void, size: usize, align: usize);

static mut ALLOC_FN: Option<AllocFn> = None;
static mut DEALLOC_FN: Option<DeallocFn> = None;

#[no_mangle]
pub unsafe extern "C" fn pk_set_allocator(
    alloc_fn: Option<AllocFn>,
    dealloc_fn: Option<DeallocFn>,
) {
    ALLOC_FN = alloc_fn;
    DEALLOC_FN = dealloc_fn;
}

struct FfiAllocator;

unsafe impl GlobalAlloc for FfiAllocator {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match ALLOC_FN {
            Some(f) => f(layout.size(), layout.align()) as *mut u8,
            None => std::alloc::System.alloc(layout),
        }
    }

    #[inline(always)]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match DEALLOC_FN {
            Some(f) => f(ptr as *mut c_void, layout.size(), layout.align()),
            None => std::alloc::System.dealloc(ptr, layout),
        }
    }

    #[inline(always)]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        match ALLOC_FN {
            Some(f) => {
                let ptr = f(layout.size(), layout.align()) as *mut u8;
                if !ptr.is_null() {
                    ptr::write_bytes(ptr, 0, layout.size());
                }
                ptr
            }
            None => std::alloc::System.alloc_zeroed(layout),
        }
    }

    #[inline(always)]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        match (ALLOC_FN, DEALLOC_FN) {
            (Some(alloc), Some(dealloc)) => {
                let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
                let new_ptr = alloc(new_layout.size(), new_layout.align()) as *mut u8;
                if !new_ptr.is_null() {
                    ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                    dealloc(ptr as *mut c_void, layout.size(), layout.align());
                }
                new_ptr
            }
            _ => std::alloc::System.realloc(ptr, layout, new_size),
        }
    }
}

#[global_allocator]
static ALLOCATOR: FfiAllocator = FfiAllocator;
