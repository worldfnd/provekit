use crate::reification::ReifiedRegister;

#[derive(Clone, Debug)]
pub struct Variable<R> {
    pub(crate) label: String,
    pub(crate) registers: Vec<R>,
}

/// A generic instruction representation that can work with different register types.
///
/// This instruction models both regular machine instructions and register aliases.
/// It contains the opcode, result registers, operand registers, and any modifiers.
///
/// # Type Parameters
///
/// * `R` - The register type is either `FreshRegister` for virtual registers
///   or `HardwareRegister` for physical machine registers.
#[derive(Debug, PartialEq)]
pub struct Instruction<R> {
    pub(crate) opcode: String,
    // Result is a vector because:
    // - Some operations have do not write results to a register
    //   - CMN only affects flags
    //   - STR writes to a destination stored in operands
    // - LDP has 2 destinations
    pub(crate) results: Vec<ReifiedRegister<R>>,
    pub(crate) operands: Vec<ReifiedRegister<R>>,
    pub(crate) modifiers: Modifier,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Modifier {
    None,
    Imm(u64),
    ImmLsl(u16, u8),
    // Logical shift left
    Lsl(u8),
    Cond(String),
}

impl<R: std::fmt::Display> std::fmt::Display for Instruction<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let regs: String = self
            .extract_registers()
            .map(|x| x.to_string())
            .intersperse(", ".to_string())
            .collect();

        let extra = match &self.modifiers {
            Modifier::None => String::new(),
            Modifier::Imm(imm) => format!(", #{imm}"),
            Modifier::Cond(cond) => format!(", {cond}"),
            Modifier::ImmLsl(imm, shift) => format!(", #{imm}, lsl {shift}"),
            Modifier::Lsl(imm) => format!(", #{imm}"),
        };

        let inst = &self.opcode;
        write!(f, "{inst} {regs}{extra}")
    }
}

impl<R> Instruction<R> {
    /// Returns an iterator over all registers referenced by this instruction.
    ///
    /// The iterator includes both result registers and operand registers.
    pub(crate) fn extract_registers(&self) -> impl Iterator<Item = &ReifiedRegister<R>> {
        self.results.iter().chain(&self.operands)
    }
}

/// A virtual register identifier used before hardware register allocation.
///
/// FreshRegister represents a unique label for a variable in the intermediate
/// representation. It serves as a placeholder for a hardware register that will
/// be assigned during the register allocation phase.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FreshRegister(pub(crate) u64);

impl std::fmt::Display for FreshRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for FreshRegister {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// Represents a physical hardware register.
///
/// HardwareRegister is a wrapper around a register number that identifies
/// a specific register in the target CPU architecture.
#[derive(PartialEq, Debug, Hash, Ord, PartialOrd, Eq, Clone, Copy)]
pub struct HardwareRegister(pub(crate) u64);

impl std::fmt::Display for HardwareRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a basic hardware register with its type (general or vector).
///
/// BasicRegister describes a physical register as it is contained within the
/// register banks. It does not have any kind information nor indexing.
#[derive(Clone, Copy, PartialEq, Debug, Eq, Ord, PartialOrd)]
pub enum TypedHardwareRegister {
    /// A general purpose register (like x0-x31 on ARM64)
    General(HardwareRegister),
    /// A vector register (like v0-v31 on ARM64)
    Vector(HardwareRegister),
}

impl TypedHardwareRegister {
    /// Extracts the hardware register number from the basic register.
    pub(crate) fn reg(&self) -> HardwareRegister {
        match self {
            TypedHardwareRegister::General(reg) | TypedHardwareRegister::Vector(reg) => *reg,
        }
    }
}

impl std::fmt::Display for TypedHardwareRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypedHardwareRegister::General(reg) => write!(f, "x{}", reg.0),
            TypedHardwareRegister::Vector(reg) => write!(f, "v{}", reg.0),
        }
    }
}
