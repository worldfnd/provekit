# RISC-V zkVM Example

This Noir example implements a zkVM that interprets the same RV32IM instruction set executed by Risc0 and Succinct's SP1. The circuit enforces the semantics of the full integer base ISA along with the `M` multiplication/division extension over a bounded execution trace, tracking both the 32-register file and a byte-addressable main memory.

## Circuit interface

The circuit exposes the following public inputs:

* `program`: a fixed-size array of 32-bit instructions representing the executable image.
* `program_len`: the number of valid instructions present in `program`.
* `num_steps`: the length of the execution trace to check.
* `program_base_pc`: the address corresponding to `program[0]`.
* `initial_pc` and `initial_regs`: the starting program counter and register file snapshot.
* `initial_memory`: the starting contents of the emulated main memory (little-endian `u32` words covering four bytes each).
* `expected_final_pc`, `expected_final_regs`, and `expected_final_memory`: the post-execution state that the circuit must reproduce.

The prover commits to the complete instruction trace (potentially containing control-flow divergence such as branches and jumps) and the circuit recomputes each state transition using the RV32IM semantics. All reads and writes pass through the `x0` zero register constraint, memory byte/halfword/word loads and stores, arithmetic/logical operations, and the full set of multiply/divide/remainder instructions.

## Example witness

The supplied `Prover.toml` drives a small program that:

1. Loads `x1 = 5` and `x2 = 7`.
2. Adds the values into `x3` and stores them to memory.
3. Exercises a taken branch to skip an instruction.
4. Computes `x5 = x1 * x2` via the `MUL` opcode.
5. Performs a `JAL` to skip another instruction and finally reloads the stored value with `LW`.

The expected registers, memory word, and final program counter are asserted as public outputs so the verifier can check that the entire trace was executed correctly.

Run the example with `nargo prove` and `nargo verify` from this directory once you have Noir installed.
