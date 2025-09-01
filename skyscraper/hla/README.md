# HLA (High-Level Assembler) 

## Overview

HLA provides a convenient way for writing and generating assembly code for the ARM64 architecture with Rust as the macro language and Clang/LLVM as the assembler. The primary purpose of the HLA is to simplify the interleaving of multiple implementations of an algorithm, enabling the combined version to utilize different execution units concurrently in a robust and reliable way. For example, an algorithm performing Montgomery multiplication and reduction can be implemented using both floating-point SIMD instructions and regular integer multiplication. Because these operations target different CPU pipelines, we can exploit instruction-level parallelism to achieve higher throughput.

Achieving robust and reliable interleaving is particularly challenging when implementing in Rust. Compiler optimizations can freely reorder instructions often disrupting the designed instruction-level parallelism and small changes to the source lead to unpredictable changes in performance. While Rust supports inline assembly it does not expose an interface that would allow for interleaving. 
 
## Key Components

The architecture is organized around several components:
- Frontend
    - Frontend.rs - The main API used when writing assembly. 
        - Reg<T> represents a hardware register containing a primitive type T. Simd<T,2> is also considered a primitive type as it fits in a vector register. 
        - Complex types/variables are arrays or tuples of Reg<T>
        - The .as_() and .into_() functions provide a way to cast registers.
        - Sized + Idx provide a way to select lanes within Reg<Simd<T,2>>
    - Instructions.rs - ARM instructions are implemented as functions. 
        - When adding instructions use the type signature to restrict it use as much as needed. Keep in mind that when including the assembly into Rust it goes through clang/llvm so you can delegate some of the responsibility to clang/llvm. 
        - Instructions were introduced only when necessary, and designed to be no more generic than needed.
    - Reification.rs - handles transformations from frontend register representation to the intermediate representation
- IR - represents assembly instructions in a generic way. 
- Backend
    - Liveness Analysis - analysis when fresh registers can be dropped
    - Backend - uses the result of the liveness analysis for the allocation of hardware registers
    - Code Generation: produces the final assembly code. 
        - This can be a stand-alone assembly or inline rust assembly. The latter is useful to let the Rust compiler plan how registers should be saved before calling the assembly code. 
- Builder - orchestrates the entire pipeline and combines different algorithm implementation into a single one.



