use {
    crate::{
        FreshVariable,
        ir::{FreshRegister, HardwareRegister, Instruction, TypedHardwareRegister, Variable},
        liveness::{Lifetime, Lifetimes},
        reification::{Index, RegisterType, ReifiedRegister},
    },
    std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
};

pub type AllocatedVariable = Variable<TypedHardwareRegister>;

#[derive(Debug)]
struct RegisterAllocator {
    // Keeps track of the free hardware during allocations
    free_registers: BTreeSet<HardwareRegister>,
    // Registers that at the end should contain the outputs
    pinned:         PinnedOutputRegisters,
}

#[derive(Debug)]
struct PinnedOutputRegisters {
    // Acts as a concrete iterator to keep track of which register are free to
    // to hold output variables.
    // We use a BTreeSet as "iterator" here to also support ABI like SYS-V which
    // might use a few low numbered registers and x8.
    iter:         BTreeSet<HardwareRegister>,
    // Keep track till when the pinned output register is free to be used
    // for other variables.
    reservations: BTreeMap<HardwareRegister, (FreshRegister, usize)>,
}

impl PinnedOutputRegisters {
    fn new(iter: impl Iterator<Item = u64>) -> Self {
        Self {
            iter:         BTreeSet::from_iter(iter.map(HardwareRegister)),
            reservations: BTreeMap::new(),
        }
    }

    // Return True on successful reservation
    fn reserve_output_register(
        &mut self,
        lifetimes: &Lifetimes,
        reified_register: &ReifiedRegister<FreshRegister>,
    ) -> bool {
        match self.iter.pop_first() {
            Some(hardware_register) => {
                let lifetime = lifetimes[reified_register.reg].begin;

                self.reservations
                    .insert(hardware_register, (reified_register.reg, lifetime));
                true
            }
            None => false,
        }
    }
}

impl RegisterAllocator {
    fn new<T>(registers: T) -> Self
    where
        T: Iterator<Item = u64> + Clone,
    {
        let pool = BTreeSet::from_iter(registers.clone().map(HardwareRegister));
        RegisterAllocator {
            free_registers: pool,
            pinned:         PinnedOutputRegisters::new(registers),
        }
    }

    fn pop_first(&mut self, reg: FreshRegister, end_lifetime: usize) -> Option<HardwareRegister> {
        // Find the first register that is free and will be free for the entirety of the
        // lifetime of the fresh register.
        let reg = self
            .free_registers
            .iter()
            .find(
                // Check if the hardware register has been preassigned assigned to this fresh
                // registers Check if the hardware register can be used before it's
                // preassigned moment
                |&hardware_register| match self.pinned.reservations.get(hardware_register) {
                    Some((tp, _lifetime)) if reg == *tp => true,
                    Some((_tp, lifetime)) if end_lifetime <= *lifetime => true,
                    // Hardware register has not been preassigned
                    None => true,
                    // Hardware register was preassigned to a different fresh register and it's
                    // ownership overlaps with the lifetime of reg
                    _ => false,
                },
            )
            .copied();

        // Remove the register from the pool if found
        if let Some(hardware_register) = reg {
            self.free_registers.remove(&hardware_register);
        }

        reg
    }

    fn insert(&mut self, register: HardwareRegister) -> bool {
        self.free_registers.insert(register)
    }
}

pub fn allocate_input_variable(
    mapping: &mut RegisterMapping,
    register_bank: &mut RegisterBank,
    input_hw_registers: Vec<FreshVariable>,
    lifetimes: &Lifetimes,
) -> Vec<AllocatedVariable> {
    input_hw_registers
        .into_iter()
        .map(|variable| {
            let registers = variable
                .registers
                .into_iter()
                .map(|register| {
                    mapping
                        .get_or_allocate_register(register_bank, register, lifetimes[register.reg])
                        .to_basic_register()
                })
                .collect();
            AllocatedVariable {
                label: variable.label,
                registers,
            }
        })
        .collect()
}

/// Pins a fresh register to a specific hardware register.
///
/// This function assigns a specific hardware register to a fresh register,
/// ensuring that register allocation will use the specified hardware register.
///
/// # Arguments
///
/// * `register_bank` - RegisterBank to pin the register in
/// * `lifetimes` - Register lifetimes for allocation planning. It will use the
///   begin value.
pub fn reserve_output_variable(
    register_bank: &mut RegisterBank,
    lifetimes: &Lifetimes,
    variable: &FreshVariable,
) {
    let pool = register_bank.get_register_pool(variable.registers[0].r#type);
    for reified_register in &variable.registers {
        if !pool
            .pinned
            .reserve_output_register(lifetimes, reified_register)
        {
            panic!(
                "Ran out of registers to reserve {}! Reduce the number of outputs.",
                variable.label
            )
        }
    }
}

/// Manages pools of hardware registers for allocation.
///
/// RegisterBank maintains separate pools for general-purpose registers and
/// vector registers. It handles allocation and deallocation of hardware
/// registers.
#[derive(Debug)]
pub struct RegisterBank {
    general_purpose: RegisterAllocator,
    vector:          RegisterAllocator,
}

impl Default for RegisterBank {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterBank {
    /// Creates a new RegisterBank with default register pools.
    ///
    /// # Returns
    ///
    /// A new RegisterBank with general-purpose and vector register pools.
    /// Certain registers are excluded:
    /// - Register 18 (reserved by OS)
    /// - Register 19 (reserved by LLVM)
    /// - Register 30 (reserved for link register)
    /// - Register 31 (reserved for stack pointer)
    pub fn new() -> Self {
        Self {
            general_purpose: RegisterAllocator::new((0..=17).chain(20..29)),
            vector:          RegisterAllocator::new(0..=31),
        }
    }

    /// Gets the appropriate register pool based on register type.
    ///
    /// # Arguments
    ///
    /// * `r#type` - The register type (X, V, or D)
    ///
    /// # Returns
    ///
    /// A mutable reference to the corresponding register pool.
    fn get_register_pool(&mut self, r#type: RegisterType) -> &mut RegisterAllocator {
        match r#type {
            RegisterType::X => &mut self.general_purpose,
            RegisterType::V | RegisterType::D => &mut self.vector,
        }
    }

    /// Allocates a hardware register for a fresh register.
    ///
    /// # Arguments
    ///
    /// * `tp` - The fresh register to allocate for
    /// * `end_lifetime` - The instruction index after which the register is no
    ///   longer needed
    ///
    /// # Returns
    ///
    /// An Option containing the allocated hardware register, or None if
    /// allocation failed.
    fn pop_first(
        &mut self,
        reified_register: ReifiedRegister<FreshRegister>,
        end_lifetime: usize,
    ) -> Option<ReifiedRegister<HardwareRegister>> {
        let hw_reg = self
            .get_register_pool(reified_register.r#type)
            .pop_first(reified_register.reg, end_lifetime);

        hw_reg.map(|reg| reified_register.into_hardware(reg))
    }

    /// Returns a hardware register back to the register pool.
    ///
    /// # Returns
    ///
    /// `true` if the register was added to the pool, `false` if it was already
    /// in the pool.
    fn insert(&mut self, register: TypedHardwareRegister) -> bool {
        match register {
            TypedHardwareRegister::General(hardware_register) => {
                self.general_purpose.insert(hardware_register)
            }
            TypedHardwareRegister::Vector(hardware_register) => {
                self.vector.insert(hardware_register)
            }
        }
    }
}

/// Maps fresh registers to their assigned hardware registers.
///
/// RegisterMapping maintains the mapping between virtual registers
/// (FreshRegisters) and their corresponding physical hardware registers
/// _during_ register allocation. It represents the active set of allocations.
#[derive(Debug, Default)]
pub struct RegisterMapping {
    mapping: HashMap<FreshRegister, TypedHardwareRegister>,
}

impl RegisterMapping {
    /// Creates a new empty RegisterMapping.
    pub fn new() -> Self {
        Self {
            mapping: HashMap::with_capacity(100),
        }
    }

    /// Returns the number of registers currently allocated.
    pub fn allocated(&self) -> usize {
        self.mapping.len()
    }

    /// Gets the physical register for an operand.
    ///
    /// # Arguments
    ///
    /// * `fresh` - The reified fresh register to look up
    ///
    /// # Returns
    ///
    /// The corresponding hardware register.
    ///
    /// # Panics
    ///
    /// Panics if the register has not been assigned yet.
    fn get_register(
        &self,
        fresh: ReifiedRegister<FreshRegister>,
    ) -> ReifiedRegister<HardwareRegister> {
        match self.mapping.get(&fresh.reg) {
            Some(reg) => fresh.into_hardware(reg.reg()),
            None => panic!(
                "Internal error: {fresh:?} has not been assigned yet. This should not be possible."
            ),
        }
    }

    /// Gets or allocates a register.
    ///
    /// If the register is already mapped, returns the existing mapping.
    /// Otherwise, allocates a new hardware register.
    ///
    /// # Arguments
    ///
    /// * `register_bank` - The register bank to allocate from
    /// * `typed_register` - The fresh register to get or allocate
    /// * `end_lifetime` - The instruction index after which the register is no
    ///   longer needed
    ///
    /// # Returns
    ///
    /// The corresponding hardware register.
    ///
    /// # Panics
    ///
    /// Panics if register allocation fails.
    pub fn get_or_allocate_register(
        &mut self,
        register_bank: &mut RegisterBank,
        typed_register: ReifiedRegister<FreshRegister>,
        lifetime: Lifetime,
    ) -> ReifiedRegister<HardwareRegister> {
        // Either return existing mapping or create new one
        match self.mapping.get(&typed_register.reg) {
            Some(reg) => typed_register.into_hardware(reg.reg()),
            None => {
                let hardware_reified_register = register_bank
                    .pop_first(typed_register, lifetime.end)
                    .unwrap_or_else(|| {
                        panic!(
                            "All register are in use. HLA does not support spilling to stack for \
                             performance reasons. Reduce the number of registers simultaneously \
                             in use."
                        )
                    });

                self.mapping.insert(
                    typed_register.reg,
                    hardware_reified_register.to_basic_register(),
                );
                hardware_reified_register
            }
        }
    }

    /// Frees a register, returning it to the register bank.
    ///
    /// # Returns
    ///
    /// `true` if the register was freed, `false` otherwise.
    fn free_register(&mut self, register_bank: &mut RegisterBank, fresh: FreshRegister) -> bool {
        if let Some(reg) = self.mapping.remove(&fresh) {
            let result = register_bank.insert(reg);
            assert!(
                result,
                "hardware:{reg:?} is assigned to more than one fresh register."
            );
            result
        } else {
            panic!(
                "Trying to free a fresh register that has not been assigned a hardware register: \
                 {fresh}"
            )
        }
    }

    pub fn get_allocated_variable(&mut self, variable: &FreshVariable) -> AllocatedVariable {
        AllocatedVariable {
            label:     variable.label.clone(),
            registers: variable
                .registers
                .iter()
                .map(|register| {
                    {
                        self.mapping
                            .get(&register.reg)
                            .map(|hw_reg| {
                                ReifiedRegister {
                                    reg:    hw_reg.reg(),
                                    r#type: register.r#type,
                                    idx:    Index::None,
                                }
                                .to_basic_register()
                            })
                            .unwrap_or_else(|| {
                                panic!("Internal error: {} has not been allocated.", variable.label)
                            })
                    }
                })
                .collect(),
        }
    }
}

/// Allocates hardware registers for a sequence of instructions.
///
/// This function transforms instructions using fresh registers into
/// instructions using hardware registers, performing register allocation based
/// on the results of liveness analysis.
///
/// # Arguments
///
/// * `mapping` - The register mapping to use and update
/// * `register_bank` - The register bank to allocate from
/// * `instructions` - The instruction sequence using fresh registers
/// * `releases` - The registers to release after each instruction
/// * `lifetimes` - The lifetime information for each register
///
/// # Returns
///
/// A new sequence of instructions using hardware registers.
///
/// # Panics
///
/// Panics if the instructions and releases collections have different lengths.
pub fn hardware_register_allocation(
    mapping: &mut RegisterMapping,
    register_bank: &mut RegisterBank,
    instructions: Vec<Instruction<FreshRegister>>,
    releases: VecDeque<HashSet<FreshRegister>>,
    lifetimes: Lifetimes,
) -> Vec<Instruction<HardwareRegister>> {
    assert_eq!(
        instructions.len(),
        releases.len(),
        "The instructions and release collections need to be the same length"
    );

    instructions
        .into_iter()
        .zip(releases)
        .map(|(instruction, release)| {
            // Map operands to hardware registers
            let src = instruction
                .operands
                .into_iter()
                .map(|s| mapping.get_register(s))
                .collect();

            // Free registers that are no longer needed
            release.into_iter().for_each(|fresh| {
                mapping.free_register(register_bank, fresh);
            });

            // Allocate result registers
            let dest = instruction
                .results
                .into_iter()
                .map(|d| {
                    let idx = d.reg;
                    mapping.get_or_allocate_register(register_bank, d, lifetimes[idx])
                })
                .collect();

            // Construct the hardware instruction
            Instruction {
                opcode:    instruction.opcode,
                results:   dest,
                operands:  src,
                modifiers: instruction.modifiers,
            }
        })
        .collect()
}
