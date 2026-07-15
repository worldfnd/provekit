//! Dual-mode allocator: callback-based or pure Rust mmap.
//!
//! Supports two modes:
//! 1. Callback mode: Delegates to host (Swift) via FFI callbacks
//! 2. Mmap mode: Pure Rust mmap-based allocation (no FFI overhead)
//!
//! SAFETY: pk_set_allocator must be called before any allocations occur.
//! Once allocations have started, switching modes is undefined behavior.

use std::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

type AllocFn = unsafe extern "C" fn(size: usize, align: usize) -> *mut c_void;
type DeallocFn = unsafe extern "C" fn(ptr: *mut c_void, size: usize, align: usize);

static ALLOC_FN: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());
static DEALLOC_FN: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Mode selector: true = use mmap allocator, false = use callbacks
static USE_MMAP_ALLOCATOR: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub unsafe extern "C" fn pk_set_allocator(
    alloc_fn: Option<AllocFn>,
    dealloc_fn: Option<DeallocFn>,
) {
    // If both are None and mmap allocator is configured, use mmap mode
    if alloc_fn.is_none() && dealloc_fn.is_none() {
        if crate::mmap_allocator::is_configured() {
            USE_MMAP_ALLOCATOR.store(true, Ordering::Release);
            ALLOC_FN.store(ptr::null_mut(), Ordering::Release);
            DEALLOC_FN.store(ptr::null_mut(), Ordering::Release);
            return;
        }
    }

    // Otherwise use callback mode
    USE_MMAP_ALLOCATOR.store(false, Ordering::Release);

    // Store function pointers atomically (transmute fn ptr -> *mut ())
    let alloc_ptr = alloc_fn.map(|f| f as *mut ()).unwrap_or(ptr::null_mut());
    let dealloc_ptr = dealloc_fn.map(|f| f as *mut ()).unwrap_or(ptr::null_mut());

    ALLOC_FN.store(alloc_ptr, Ordering::Release);
    DEALLOC_FN.store(dealloc_ptr, Ordering::Release);
}

struct FfiAllocator;

/// Load alloc function pointer atomically
#[inline(always)]
fn load_alloc_fn() -> Option<AllocFn> {
    let ptr = ALLOC_FN.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut (), AllocFn>(ptr) })
    }
}

/// Load dealloc function pointer atomically
#[inline(always)]
fn load_dealloc_fn() -> Option<DeallocFn> {
    let ptr = DEALLOC_FN.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut (), DeallocFn>(ptr) })
    }
}

unsafe impl GlobalAlloc for FfiAllocator {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Check if we should use mmap allocator
        if USE_MMAP_ALLOCATOR.load(Ordering::Relaxed) {
            return crate::mmap_allocator::MMAP_ALLOCATOR.alloc(layout);
        }

        // Fallback to callback or system allocator
        match load_alloc_fn() {
            Some(f) => f(layout.size(), layout.align()) as *mut u8,
            None => std::alloc::System.alloc(layout),
        }
    }

    #[inline(always)]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Check if we should use mmap allocator
        if USE_MMAP_ALLOCATOR.load(Ordering::Relaxed) {
            return crate::mmap_allocator::MMAP_ALLOCATOR.dealloc(ptr, layout);
        }

        // Fallback to callback or system allocator
        match load_dealloc_fn() {
            Some(f) => f(ptr as *mut c_void, layout.size(), layout.align()),
            None => std::alloc::System.dealloc(ptr, layout),
        }
    }

    #[inline(always)]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // For mmap allocator, delegate (it handles zeroing)
        if USE_MMAP_ALLOCATOR.load(Ordering::Relaxed) {
            return crate::mmap_allocator::MMAP_ALLOCATOR.alloc_zeroed(layout);
        }

        // Callback mode
        match load_alloc_fn() {
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
        // For mmap allocator, delegate (it handles realloc properly)
        if USE_MMAP_ALLOCATOR.load(Ordering::Relaxed) {
            return crate::mmap_allocator::MMAP_ALLOCATOR.realloc(ptr, layout, new_size);
        }

        // Callback mode
        let alloc_fn = load_alloc_fn();
        let dealloc_fn = load_dealloc_fn();

        match (alloc_fn, dealloc_fn) {
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
