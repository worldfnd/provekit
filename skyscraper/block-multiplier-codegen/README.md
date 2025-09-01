# Block Multiplier Codegen

This crate contains a binary that generates optimized assembly code for block multiplication using Montgomery arithmetic.

## Usage

1.  **Run the binary:**
    ```bash
    cargo run --package block-multiplier-codegen
    ```
    This will execute the `main` function in `src/main.rs`.

2.  **Generated File:**
    The binary will generate an assembly file named `asm/montgomery_interleaved.s` within this crate's directory.

3.  **Integrate into `block-multiplier-sys`:**
    Copy the contents of the generated `asm/montgomery_interleaved.s` file. Paste this assembly code into the appropriate location within the `block-multiplier-sys` crate, likely inside a specific function designed to use this inline assembly. 