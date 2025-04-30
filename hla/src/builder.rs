use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::Path;

use crate::AtomicInstructionBlock;
use crate::backend::{
    AllocatedVariable, RegisterBank, RegisterMapping, allocate_input_variable,
    hardware_register_allocation, reserve_output_variable,
};
use crate::codegen::{generate_rust_global_asm, generate_rust_inline_asm};
use crate::frontend::{Assembler, FreshAllocator, FreshVariable};
use crate::ir::{HardwareRegister, Instruction, Variable};
use crate::liveness::liveness_analysis;

/// A function type that sets up an assembly program, returning input and output variables.
pub type Setup =
    fn(alloc: &mut FreshAllocator, asm: &mut Assembler) -> (Vec<FreshVariable>, FreshVariable);

/// Builds a single assembly function.
///
/// # Arguments
///
/// * `path` - The path where the assembly file will be written
/// * `label` - The label for the assembly function
/// * `f` - The setup function that creates the assembly
pub fn build_single<P: AsRef<Path>>(path: P, label: &str, f: Setup) {
    build_standalone(path, label, Interleaving::single(f));
}

/// Builds one or more interleaved assembly functions.
///
/// This function coordinates the entire process of assembly generation:
/// 1. Runs the setup functions to get instructions and variables
/// 2. Performs liveness analysis
/// 3. Allocates registers to variables
/// 4. Generates assembly code
/// 5. Writes the code to the specified file
///
/// # Arguments
///
/// * `path` - The path where the assembly file will be written
/// * `label` - The label for the assembly function
/// * `algos` - The interleaved setup functions
pub fn build_standalone<P: AsRef<Path>>(path: P, label: &str, algos: Interleaving<Setup>) {
    build(path, algos, |inputs, outputs, instructions| {
        generate_rust_global_asm(label, inputs, outputs, instructions)
    })
}

pub fn build_inline<P: AsRef<Path>>(path: P, algos: Interleaving<Setup>) {
    build(path, algos, generate_rust_inline_asm)
}

pub fn build<P, C>(path: P, algos: Interleaving<Setup>, codegen: C)
where
    P: AsRef<Path>,
    C: FnOnce(
        &[AllocatedVariable],
        &[AllocatedVariable],
        &[Instruction<HardwareRegister>],
    ) -> String,
{
    let mut alloc = FreshAllocator::new();
    let mut mapping = RegisterMapping::new();
    let mut register_bank = RegisterBank::new();

    let (input_hw_registers, output_hw_registers, instructions) = run_setups(&mut alloc, algos);

    // We do not check for unique_variables across inputs and outputs. For example when using a input pointer as output as well the name
    // should be the same.
    let input_hw_registers = unique_variable(input_hw_registers);
    let output_hw_registers = unique_variable(output_hw_registers);

    let instructions: Vec<_> = instructions.into_iter().flatten().collect();

    let (releases, lifetimes) = liveness_analysis(&alloc, &output_hw_registers, &instructions);

    let input_hw_registers = allocate_input_variable(
        &mut mapping,
        &mut register_bank,
        input_hw_registers,
        &lifetimes,
    );

    output_hw_registers.iter().for_each(|variable| {
        reserve_output_variable(&mut register_bank, &lifetimes, variable);
    });

    let hardware_instructions = hardware_register_allocation(
        &mut mapping,
        &mut register_bank,
        instructions,
        releases,
        lifetimes,
    );

    let output_hw_registers: Vec<_> = output_hw_registers
        .iter()
        .map(|fresh_variable| mapping.get_allocated_variable(fresh_variable))
        .collect();

    // Write this info in the assembly file
    let assembly = codegen(
        &input_hw_registers,
        &output_hw_registers,
        &hardware_instructions,
    );

    use std::io::Write;
    let mut file = std::fs::File::create(&path)
        .unwrap_or_else(|_| panic!("Unable to create file: {:#?}", path.as_ref()));
    file.write_all(assembly.as_bytes())
        .unwrap_or_else(|_| panic!("Unable to write assembly to file: {:#?}", path.as_ref()));
}

/// Runs setup functions according to their interleaving pattern.
///
/// # Arguments
///
/// * `alloc` - The fresh register allocator
/// * `algos` - The interleaved setup functions
///
/// # Returns
///
/// A tuple containing input variables, output variables, and instruction blocks
fn run_setups(
    alloc: &mut FreshAllocator,
    algos: Interleaving<Setup>,
) -> (
    Vec<FreshVariable>, // inputs
    Vec<FreshVariable>, // outputs
    Vec<AtomicInstructionBlock>,
) {
    match algos {
        Interleaving::Seq(items) => items.into_iter().fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(mut inputs, mut outputs, mut instructions), func| {
                let (input, output, instrs) = run_setup(alloc, func);
                inputs.extend(input);
                outputs.push(output);
                instructions.extend(instrs);
                (inputs, outputs, instructions)
            },
        ),
        Interleaving::Par(left, right) => {
            let (inputs_left, outputs_left, instructions_left) = run_setups(alloc, *left);
            let (inputs_right, outputs_right, instructions_right) = run_setups(alloc, *right);

            let mut inputs = inputs_left;
            inputs.extend(inputs_right);

            let mut outputs = outputs_left;
            outputs.extend(outputs_right);

            let instructions = interleave(instructions_left, instructions_right);

            (inputs, outputs, instructions)
        }
    }
}

/// Runs a single setup function.
///
/// # Returns
///
/// A tuple containing input variables, the output variable, and instruction blocks
fn run_setup(
    alloc: &mut FreshAllocator,
    f: Setup,
) -> (
    Vec<FreshVariable>,
    FreshVariable,
    Vec<AtomicInstructionBlock>,
) {
    let mut asm = Assembler::new();
    let (inputs, outputs) = f(alloc, &mut asm);
    (inputs, outputs, asm.instructions)
}

/// Ensures all variable labels are unique by adding incremental numbers to duplicates.
///
/// When multiple variables would have the same label, this function adds numbers
/// to make them unique (e.g., "var" becomes "var1", "var2", etc.).
///
/// # Arguments
///
/// * `variables` - A vector of variables that might contain duplicate labels
///
/// # Returns
///
/// A new vector with the same variables but unique labels
fn unique_variable<T>(variables: Vec<Variable<T>>) -> Vec<Variable<T>> {
    let mut variable_count: HashMap<String, u8> = HashMap::new();

    variables
        .into_iter()
        .map(|variable| {
            let label = variable.label.clone();

            match variable_count.entry(label.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(1);
                    variable
                }
                Entry::Occupied(mut entry) => {
                    let count = entry.get_mut();
                    let new_label = format!("{}{}", label, *count);
                    *count += 1;

                    Variable {
                        label: new_label,
                        registers: variable.registers,
                    }
                }
            }
        })
        .collect()
}

/// Represents how setup functions should be executed and their instructions combined.
///
/// This enum allows for sequential or parallel execution patterns of setup functions.
/// - `Seq` - Functions are executed sequentially, with their instructions appearing in order
/// - `Par` - Functions from both branches are executed, with their instructions interleaved
pub enum Interleaving<T> {
    /// Sequential execution of setup functions
    Seq(Vec<T>),
    /// Parallel execution with instructions interleaved
    Par(Box<Interleaving<T>>, Box<Interleaving<T>>),
}

impl<T> Interleaving<T> {
    /// Creates an interleaving with a single item.
    pub fn single(t: T) -> Self {
        Interleaving::Seq(vec![t])
    }

    /// Places assembly instructions after each other
    pub fn seq(t: Vec<T>) -> Self {
        Interleaving::Seq(t)
    }

    /// Creates a parallel interleaving from two existing interleavings.
    ///
    /// # Arguments
    ///
    /// * `t1` - First interleaving branch
    /// * `t2` - Second interleaving branch
    ///
    /// # Returns
    ///
    /// A new parallel interleaving that combines both branches
    pub fn par(t1: Interleaving<T>, t2: Interleaving<T>) -> Self {
        Interleaving::Par(Box::new(t1), Box::new(t2))
    }
}

/// Interleaves elements from two vectors.
///
/// This function combines elements from two vectors, distributing the elements
/// from the shorter vector evenly throughout the longer vector.
///
/// # Arguments
///
/// * `lhs` - First vector of elements
/// * `rhs` - Second vector of elements
///
/// # Returns
///
/// A new vector containing all elements from both input vectors, interleaved.
fn interleave<T>(lhs: Vec<T>, rhs: Vec<T>) -> Vec<T> {
    let (shorter, longer) = if lhs.len() <= rhs.len() {
        (lhs, rhs)
    } else {
        (rhs, lhs)
    };

    if shorter.is_empty() {
        return longer;
    }

    let mut result = Vec::with_capacity(shorter.len() + longer.len());

    let short_len = shorter.len();
    let mut short_iter = shorter.into_iter().enumerate();

    let long_len = longer.len();
    let mut long_iter = longer.into_iter();
    // For the first element (short_index = 0 ) -> The location will be ((short_index + 1) * long_len) / short_len
    let mut next = long_len / short_len;

    // With spacing i needs to reach and place the last element of short
    // ((short_len - 1 + 1) * long_len) / short_len = long_len. Therefore the range is 0..=long_len
    for i in 0..=long_len {
        if i == next {
            if let Some((short_index, item)) = short_iter.next() {
                result.push(item);
                // Order is important due to flooring
                // next = index next element (short_index + 1) + 1
                next = ((short_index + 2) * long_len) / short_len;
            }
        }

        if let Some(item) = long_iter.next() {
            result.push(item)
        }
    }

    assert!(short_iter.next().is_none());

    result
}

#[cfg(test)]
mod test {
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn interleave(lhs: Vec<u64>, rhs: Vec<u64>) -> bool {
        let left = lhs.len();
        let right = rhs.len();
        let res = super::interleave(lhs, rhs);
        res.len() == left + right
    }
}
