//! Code generators that do ~90% of the work required to incorporate an assembly function into Rust.
//! It will generate the meat of the functions, the assembly instructions and in/out/lateout for registers, but you'll have to write the interface functions and
//! for loads/store you'll need to modify the argument a little bit.
use std::collections::BTreeSet;

use crate::backend::AllocatedVariable;
use crate::ir::{HardwareRegister, Instruction, TypedHardwareRegister};

pub fn generate_standalone_asm(
    label: &str,
    instructions: &[Instruction<HardwareRegister>],
) -> String {
    let label = format!("_{label}");

    let formatted_instructions: String = instructions
        .iter()
        // tab instructions by two spaces
        .map(|instruction| format!("  {}", instruction))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"
.global {label}
.align 4
.text
{label}:
{formatted_instructions}
  ret"#
    )
}

pub fn format_instructions_rust_inline(instructions: &[Instruction<HardwareRegister>]) -> String {
    instructions
        .iter()
        .map(|instruction| format!("\"{}\"", instruction))
        .collect::<Vec<_>>()
        .join(",\n")
}

/// Generate a standalone file to be used with global_asm!. The top of file will include a comment
/// that can be used as basis for the operands in global_asm!.
pub fn generate_rust_global_asm(
    label: &str,
    inputs_registers: &[AllocatedVariable],
    outputs_registers: &[AllocatedVariable],
    instructions: &[Instruction<HardwareRegister>],
) -> String {
    let operands = generate_asm_operands(inputs_registers, outputs_registers, instructions);
    let standalone = generate_standalone_asm(label, instructions);

    let operands_with_comments: String = operands
        .lines()
        .map(|line| format!("//{line}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"{operands_with_comments}
        {standalone}"#
    )
}

pub fn generate_rust_inline_asm(
    inputs_registers: &[AllocatedVariable],
    outputs_registers: &[AllocatedVariable],
    instructions: &[Instruction<HardwareRegister>],
) -> String {
    let inst = format_instructions_rust_inline(instructions);
    let operands = generate_asm_operands(inputs_registers, outputs_registers, instructions);

    format!(
        r#"
unsafe {{ asm!(
{inst},
{operands}
    )}};"#
    )
}

pub fn generate_asm_operands(
    inputs: &[AllocatedVariable],
    outputs: &[AllocatedVariable],
    instructions: &[Instruction<HardwareRegister>],
) -> String {
    let input_operands = format_operands(inputs, "in");
    let output_operands = format_operands(outputs, "lateout");
    let clobber_registers = get_clobber_registers(outputs, instructions);

    let clobbers = format_clobbers(&clobber_registers);

    vec![
        input_operands,
        output_operands,
        clobbers,
        "lateout(\"lr\") _".to_string(),
    ]
    .join(",\n")
}

/// Clobber registers are all the registers that have been used in the assembly block minus the
/// registers that are used for the output. These are needed by Rust to plan which registers need to be saved.
fn get_clobber_registers(
    outputs_registers: &[AllocatedVariable],
    instructions: &[Instruction<HardwareRegister>],
) -> Vec<TypedHardwareRegister> {
    let mut all_used_registers = BTreeSet::new();

    for instruction in instructions {
        all_used_registers.extend(
            instruction
                .extract_registers()
                .map(|reg| reg.to_basic_register()),
        );
    }

    let output_registers = outputs_registers
        .iter()
        .flat_map(|variable| variable.registers.clone())
        .collect();

    all_used_registers
        .difference(&output_registers)
        .cloned()
        .collect()
}

/// Formats a list of clobbered registers into the appropriate Rust inline assembly syntax.
/// Each register is formatted as "lateout("REG") _" to indicate to the Rust compiler
/// that the register is clobbered and needs to be saved.
///
/// # Arguments
///
/// * `clobbered_registers` - The list of registers that need to be marked as clobbered
///
/// # Returns
///
fn format_clobbers(clobbered_registers: &[TypedHardwareRegister]) -> String {
    clobbered_registers
        .iter()
        .map(|register| format!("lateout(\"{}\") _", register))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Formats register operands for Rust inline assembly.
///
/// This function takes a variable (modelled as an array of registers) and formats them according to a provided
/// formatter function. Each variable is processed separately, with commas separating
/// registers within a group and newlines separating groups.
///
/// # Arguments
///
/// * `variables` - A slice of register vectors, where each vector represents a logical group
///   (e.g., all input registers for a particular operation)
/// * `formatter` - A function that formats a single register with its group index and position
///
/// # Returns
///
fn format_operands(variables: &[AllocatedVariable], direction: &str) -> String {
    // Process each register group (with its index)
    variables
        .iter()
        .map(move |variable| {
            // Format each register in the group (with its position index)
            if variable.registers.len() > 1 {
                variable
                    .registers
                    .iter()
                    .enumerate()
                    .map(move |(variable_index, register)| {
                        format!(
                            "{direction}(\"{register}\") {}[{variable_index}]",
                            variable.label
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ") // Collect registers within a group with comma separators
            } else {
                format!(
                    "{direction}(\"{}\") {}",
                    variable.registers[0], variable.label
                )
            }
        })
        .collect::<Vec<_>>()
        .join(",\n") // Separate groups with comma and newline
}
