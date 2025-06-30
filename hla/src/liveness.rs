use {
    crate::{
        FreshAllocator,
        frontend::FreshVariable,
        ir::{FreshRegister, Instruction},
        reification::ReifiedRegister,
    },
    std::{
        collections::{HashSet, VecDeque},
        fmt::Display,
    },
};

/// Tracks which registers have been seen during analysis.
///
/// This structure is used during liveness analysis to track which registers
/// have been processed.
struct Seen(HashSet<FreshRegister>);

impl Default for Seen {
    fn default() -> Self {
        Self::new()
    }
}

impl Seen {
    /// Creates a new empty Seen instance.
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Marks a register as seen and returns whether it was previously unseen.
    ///
    /// # Arguments
    ///
    /// * `fresh` - The register to mark
    ///
    /// # Returns
    ///
    /// `true` if the register was not previously seen, `false` otherwise.
    fn mark_register(&mut self, fresh: &ReifiedRegister<FreshRegister>) -> bool {
        self.0.insert(fresh.reg)
    }
}

#[derive(Clone, Copy)]
pub struct Lifetime {
    pub(crate) begin: usize,
    pub(crate) end:   usize,
}

pub struct Lifetimes(Vec<Lifetime>);

impl Lifetimes {
    pub fn new(nr_fresh_registers: usize) -> Self {
        Self(vec![
            Lifetime {
                begin: usize::MAX,
                end:   usize::MAX,
            };
            nr_fresh_registers
        ])
    }
}

impl std::ops::Index<FreshRegister> for Lifetimes {
    type Output = Lifetime;

    fn index(&self, index: FreshRegister) -> &Self::Output {
        &self.0[index.0 as usize]
    }
}

impl std::ops::IndexMut<FreshRegister> for Lifetimes {
    fn index_mut(&mut self, index: FreshRegister) -> &mut Self::Output {
        &mut self.0[index.0 as usize]
    }
}

/// Performs liveness analysis on instructions to determine register lifetimes.
///
/// This function analyzes the instruction sequence to determine at which
/// instructions each register is last used, allowing for register deallocation
/// at the earliest possible point.
///
/// # Arguments
///
/// * `output_registers` - The registers that contain the results at the end of
///   the instructions.
/// * `instructions` - The instruction sequence to analyze
/// * `nr_fresh_registers` - The total number of fresh registers used
///
/// # Returns
///
/// A tuple containing:
/// * A queue of sets of registers to release after each instruction
/// * A vector of (begin, end) lifetime indices for each register
///
/// # Panics
///
/// Panics if an instruction has an unused destination register.
pub fn liveness_analysis(
    alloc: &FreshAllocator, // Only used to know the size of the lifetimes allocations
    output_variables: &[FreshVariable],
    instructions: &[Instruction<FreshRegister>],
) -> (VecDeque<HashSet<FreshRegister>>, Lifetimes) {
    // Initialize the seen_registers with the output registers such that they won't
    // get released.
    let mut seen_registers = Seen::new();
    output_variables.iter().for_each(|variable| {
        variable.registers.iter().for_each(|register| {
            seen_registers.mark_register(register);
        });
    });

    // Keep track of the last line the free register is used in
    let mut lifetimes = Lifetimes::new(alloc.allocated());
    let mut commands = VecDeque::new();
    for (line, instruction) in instructions.iter().enumerate().rev() {
        let registers: HashSet<_> = instruction.extract_registers().map(|tr| tr.reg).collect();

        let release: HashSet<_> = registers.difference(&seen_registers.0).copied().collect();

        instruction.results.iter().for_each(|dest| {
            let dest = dest.reg;

            if release.contains(&dest) {
                print_instructions(instructions);
                panic!("{line}: {instruction:?} does not use the destination")
            }; // The union could be mutable

            let lifetime = &mut lifetimes[dest];
            lifetime.begin = line;
        });
        release.iter().for_each(|reg| {
            let lifetime = &mut lifetimes[*reg];
            lifetime.end = line;
            seen_registers.0.insert(*reg);
        });
        commands.push_front(release);
    }
    (commands, lifetimes)
}

/// Prints a formatted list of instructions for debugging.
fn print_instructions<R: Display>(instructions: &[Instruction<R>]) {
    instructions
        .iter()
        .enumerate()
        .for_each(|(line, inst)| println!("{line}: {inst}"));
}
