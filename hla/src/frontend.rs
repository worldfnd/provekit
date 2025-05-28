use {
    crate::{
        ir::{FreshRegister, Instruction, Variable},
        reification::{ReifiedRegister, ReifyRegister},
    },
    std::{array, marker::PhantomData, mem},
};

/// A vector of instructions representing an atomic unit of execution.
///
/// This type represents a sequence of instructions that should be executed
/// together as they rely on side effects such as flag setting that could
/// potentially be disturbed when interleaved.
pub type AtomicInstructionBlock = Vec<Instruction<FreshRegister>>;

/// A container for assembly instructions.
///
/// The Assembler maintains a collection of atomic instruction blocks that
/// make up a program. Instructions are appended to build up the program in
/// a way similar to a Write/State monad.
pub struct Assembler {
    pub instructions: Vec<AtomicInstructionBlock>,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    /// Creates a new empty Assembler.
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }

    /// Appends an atomic instruction block to the assembler.
    pub fn append_instruction(&mut self, inst: AtomicInstructionBlock) {
        self.instructions.push(inst)
    }
}

/// Generates fresh register identifiers for intermediate code.
///
/// The Allocator maintains a counter to generate unique FreshRegister
/// identifiers that represent virtual registers in the intermediate code.
#[derive(Debug)]
pub struct FreshAllocator {
    /// Counter for the fresh variable labels
    pub fresh: u64,
}

impl Default for FreshAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl FreshAllocator {
    /// Generates a new fresh register of the specified type.
    pub fn fresh<T>(&mut self) -> Reg<T> {
        let x = self.fresh;
        self.fresh += 1;
        Reg::new(x)
    }

    pub fn fresh_array<T, const N: usize>(&mut self) -> [Reg<T>; N] {
        array::from_fn(|_| self.fresh())
    }

    /// Creates a new Allocator
    pub fn new() -> Self {
        Self { fresh: 0 }
    }

    pub fn allocated(&self) -> usize {
        self.fresh as usize
    }
}

pub type FreshVariable = Variable<ReifiedRegister<FreshRegister>>;

impl FreshVariable {
    pub fn new<R>(label: &str, registers: &[R]) -> Self
    where
        R: ReifyRegister,
    {
        Self {
            label:     label.to_string(),
            registers: registers.iter().map(|reg| reg.reify()).collect(),
        }
    }
}

/// Represents a single hardware registers by modelling it as
/// a fresh variable.
/// This value does not have a clone or copy trait to prevent aliasing
/// the same register. it's mutability story is similar to interior mutability.
pub struct Reg<T> {
    pub(crate) reg: FreshRegister,
    _marker:        PhantomData<T>,
}

/// Represents a single hardware register that contains a pointer to a type T
/// and an offset from that pointer.
pub struct PointerReg<'a, T> {
    pub(crate) reg:    &'a Reg<T>,
    // offset in bytes as that allows for conversions between
    // x and w without having to recalculate the offset
    pub(crate) offset: usize,
    _marker:           PhantomData<T>,
}

pub enum Lazy<'a, T> {
    Thunk(Box<dyn Fn(&mut FreshAllocator, &mut Assembler) -> T + 'a>),
    Forced(T),
}

impl<T> Lazy<'_, T> {
    fn force(&mut self, alloc: &mut FreshAllocator, asm: &mut Assembler) {
        if let Lazy::Thunk(f) = self {
            *self = Lazy::Forced(f(alloc, asm));
        }
    }

    pub fn as_(&mut self, alloc: &mut FreshAllocator, asm: &mut Assembler) -> &T {
        self.force(alloc, asm);
        match self {
            Lazy::Forced(t) => t,
            Lazy::Thunk(_) => unreachable!(),
        }
    }

    pub fn into_(mut self, alloc: &mut FreshAllocator, asm: &mut Assembler) -> T {
        self.force(alloc, asm);
        match self {
            Lazy::Forced(t) => t,
            Lazy::Thunk(_) => unreachable!(),
        }
    }
}

impl<T, const N: usize> Reg<*mut [T; N]> {
    pub fn get(&self, index: usize) -> PointerReg<*mut T> {
        assert!(index < N, "out-of-bounds access");

        PointerReg {
            reg:     self.as_pointer(),
            offset:  mem::size_of::<T>() * index,
            _marker: PhantomData,
        }
    }
}

impl<T, const N: usize> Reg<*const [T; N]> {
    pub fn get(&self, index: usize) -> PointerReg<*const T> {
        assert!(index < N, "out-of-bounds access");

        PointerReg {
            reg:     self.as_(),
            offset:  mem::size_of::<T>() * index,
            _marker: PhantomData,
        }
    }
}

pub trait Pointer: ReifyRegister {}
impl<T> Pointer for PointerReg<'_, T> {}
impl<T> Pointer for Reg<*mut T> {}
impl<T> Pointer for Reg<*const T> {}

pub trait MutablePointer: Pointer {}
impl<T> MutablePointer for PointerReg<'_, *mut T> {}
impl<T> MutablePointer for Reg<*mut T> {}

// fmla.2d supports both a vector or vector lane as multiplier
pub trait SIMD {}
impl<T, const N: usize> SIMD for Reg<Simd<T, N>> {}
impl<T: SIMD, const I: u8> SIMD for Idx<T, I> {}

pub struct Simd<T, const N: usize>(PhantomData<T>);
pub struct Idx<T, const I: u8>(pub(crate) T);
pub struct Sized<T, const L: u8>(pub(crate) T);
pub type SizedIdx<T, const L: u8, const I: u8> = Sized<Idx<T, I>, L>;

/// When inspecting a vector as a D it has 2 elements.
/// Defined as such due to restrictions on const generics.
pub const D: u8 = 2;

pub trait Reg64Bit {}
impl Reg64Bit for u64 {}
impl Reg64Bit for f64 {}

impl<T> Reg<T> {
    pub(crate) fn new(reg: u64) -> Self {
        Self {
            reg:     reg.into(),
            _marker: Default::default(),
        }
    }
}

impl Reg<f64> {
    pub fn as_simd(&self) -> &Reg<Simd<f64, 2>> {
        unsafe { std::mem::transmute(self) }
    }
}

impl<T> Reg<Simd<T, 2>> {
    pub fn into_<D>(self) -> Reg<Simd<D, 2>> {
        unsafe { std::mem::transmute(self) }
    }

    pub fn as_<D>(&self) -> &Reg<Simd<D, 2>> {
        unsafe { std::mem::transmute(self) }
    }

    // Depending on the instruction a vector lane needs
    // to be addressed by either it's size and lane or
    // just it's lane.

    pub fn _0(&self) -> &Idx<Reg<Simd<T, 2>>, 0> {
        unsafe { std::mem::transmute(self) }
    }

    pub fn _1(&self) -> &Idx<Reg<Simd<T, 2>>, 1> {
        unsafe { std::mem::transmute(self) }
    }

    pub fn _d0(&self) -> &SizedIdx<Reg<Simd<T, 2>>, D, 0> {
        unsafe { std::mem::transmute(self) }
    }

    pub fn _d1(&self) -> &SizedIdx<Reg<Simd<T, 2>>, D, 1> {
        unsafe { std::mem::transmute(self) }
    }
}

impl<T, const N: usize> Reg<*mut [T; N]> {
    pub fn as_pointer(&self) -> &Reg<*mut T> {
        unsafe { std::mem::transmute(self) }
    }
}

impl<T> Reg<*mut T> {
    pub fn as_(&self) -> &Reg<*const T> {
        unsafe { std::mem::transmute(self) }
    }
}

impl<T, const N: usize> Reg<*const [T; N]> {
    pub fn as_(&self) -> &Reg<*const T> {
        unsafe { std::mem::transmute(self) }
    }
}

impl std::fmt::Display for Reg<u64> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "x{}", self.reg)
    }
}

impl std::fmt::Debug for Reg<u64> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "x{}", self.reg)
    }
}
