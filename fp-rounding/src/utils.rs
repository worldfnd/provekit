use core::{marker::PhantomData, ptr::read_volatile};

/// A trait only visible in this crate. This is to prevent users from
/// implementing a trait when used as a super trait.
pub trait Sealed {}

/// Marker type that is not Send or Sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NotSendSync(PhantomData<*const ()>);

/// Force the evaluation of val before an operation
/// that depends on it is executed.
#[inline(always)]
pub fn fence<T>(val: T) -> T {
    // This is based on the old black_box Criterion before it switched
    // to [`std::hint::black_box`].

    // In tests hint::black_box((mode,val)) works but according to the documentation
    // it must not be relied upon to control critical program behaviour.

    // Another option that was considered was using an empty assembly block
    //     unsafe { asm!("/*{in_var}*/", in_var = in(reg) &dummy as *const T); }
    // Which used to be in libtest albeit using the old LLVM assembly syntax and
    // from what I can tell this is what hint::black_box does under the hood.
    // It is based on [CppCon 2015: Chandler Carruth "Tuning C++: Benchmarks, and CPUs, and Compilers! Oh My!"](https://www.youtube.com/watch?v=nXaxk27zwlk&t=2445s)
    // Caveat in the talk is that this should only be used for benchmarking.

    // Compiler fences have been tried but they do not work. The compiler can see
    // that the mode has independent memory access from val and thus it doesn't
    // prevent reordering.

    // This leaves us with read_volatile which is close to C's volatile behaviour.
    // Downside of this approach is that it adds load and store instructions
    // compared to no extra instructions for black_box/empty assembly block.

    let copy = unsafe { read_volatile(&raw const val) };
    // read_volatile makes a copy, but this is an unintentional side effect.
    // Since running the destructor/Drop twice is undesirable, the memory is
    // freed up here.
    std::mem::forget(val);
    copy
}
