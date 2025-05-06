use crate::{
    frontend::*,
    ir::{FreshRegister, HardwareRegister, TypedHardwareRegister},
};

#[derive(Debug, PartialOrd, Ord, Eq, Hash, PartialEq, Clone, Copy)]
pub struct ReifiedRegister<R> {
    pub reg:           R,
    pub(crate) r#type: RegisterType,
    pub(crate) idx:    Index,
}

#[derive(Debug, Eq, PartialOrd, Ord, Hash, PartialEq, Clone, Copy)]
pub enum RegisterType {
    // Scalar
    X,
    // SIMD/FP
    V,
    D,
}

#[derive(Debug, PartialOrd, Ord, Eq, Hash, PartialEq, Clone, Copy)]
pub enum Index {
    None,
    // Some instructions require the size (.d, .s, etc) in combination with
    // a lane and other instructions require just the lane as the size is fixed
    Lane(u8),
    LaneSized(LaneCount, u8),
    // offset in bytes
    Pointer(usize),
}

#[derive(Debug, PartialOrd, Ord, Eq, Hash, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum LaneCount {
    S = 4,
    D = 2,
}

impl ReifiedRegister<FreshRegister> {
    pub fn into_hardware(self, reg: HardwareRegister) -> ReifiedRegister<HardwareRegister> {
        ReifiedRegister {
            reg,
            r#type: self.r#type,
            idx: self.idx,
        }
    }
}

impl ReifiedRegister<HardwareRegister> {
    pub fn to_basic_register(&self) -> TypedHardwareRegister {
        match self.r#type {
            RegisterType::X => TypedHardwareRegister::General(self.reg),
            RegisterType::V | RegisterType::D => TypedHardwareRegister::Vector(self.reg),
        }
    }
}

impl<R: std::fmt::Display> std::fmt::Display for ReifiedRegister<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reg = &self.reg;
        let addr = self.r#type;
        match self.idx {
            Index::None => write!(f, "{addr}{reg}"),
            Index::Lane(idx) => write!(f, "{addr}{reg}[{idx}]"),
            Index::LaneSized(lane_sizes, idx) => write!(f, "{addr}{reg}.{lane_sizes}[{idx}]"),
            Index::Pointer(offset) => write!(f, "[{addr}{reg}, #{offset}]"),
        }
    }
}

impl std::fmt::Display for LaneCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaneCount::S => write!(f, "s"),
            LaneCount::D => write!(f, "d"),
        }
    }
}

impl std::fmt::Display for RegisterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterType::V => write!(f, "v"),
            RegisterType::D => write!(f, "d"),
            RegisterType::X => write!(f, "x"),
        }
    }
}

pub trait ReifyRegister {
    fn reify(&self) -> ReifiedRegister<FreshRegister>;
}

impl<T> ReifyRegister for Reg<*mut T> {
    fn reify(&self) -> ReifiedRegister<FreshRegister> {
        self.as_().reify()
    }
}

impl<T> ReifyRegister for Reg<*const T> {
    fn reify(&self) -> ReifiedRegister<FreshRegister> {
        ReifiedRegister {
            reg:    self.reg,
            r#type: RegisterType::X,
            idx:    Index::Pointer(0),
        }
    }
}

impl<T> ReifyRegister for PointerReg<'_, T> {
    fn reify(&self) -> ReifiedRegister<FreshRegister> {
        ReifiedRegister {
            reg:    self.reg.reg,
            r#type: RegisterType::X,
            idx:    Index::Pointer(self.offset),
        }
    }
}

impl ReifyRegister for Reg<u64> {
    fn reify(&self) -> ReifiedRegister<FreshRegister> {
        ReifiedRegister {
            reg:    self.reg,
            r#type: RegisterType::X,
            idx:    Index::None,
        }
    }
}

impl ReifyRegister for Reg<f64> {
    fn reify(&self) -> ReifiedRegister<FreshRegister> {
        ReifiedRegister {
            reg:    self.reg,
            r#type: RegisterType::D,
            idx:    Index::None,
        }
    }
}

impl<T> ReifyRegister for Reg<Simd<T, 2>> {
    fn reify(&self) -> ReifiedRegister<FreshRegister> {
        ReifiedRegister {
            reg:    self.reg,
            r#type: RegisterType::V,
            idx:    Index::None,
        }
    }
}

impl<T, const I: u8> ReifyRegister for Idx<Reg<Simd<T, 2>>, I> {
    fn reify(&self) -> ReifiedRegister<FreshRegister> {
        let mut tp = self.0.reify();
        tp.idx = Index::Lane(I);
        tp
    }
}

impl<T, const L: u8, const I: u8> ReifyRegister for Sized<Idx<Reg<Simd<T, 2>>, I>, L> {
    fn reify(&self) -> ReifiedRegister<FreshRegister> {
        let mut tp = self.0.reify();

        let sizes = match L {
            2 => LaneCount::D,
            4 => LaneCount::S,
            _ => panic!("invalid lane size"),
        };

        tp.idx = Index::LaneSized(sizes, I);
        tp
    }
}
