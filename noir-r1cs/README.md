# noir-r1cs

PROTOTYPE: DO NOT USE IN PRODUCTION

### Compile and generate witness
```
nargo compile && nargo execute witness
```

### Generate R1CS
```
cargo run -- r1cs noir-examples/basic/target/basic.json noir-examples/basic/target/witness.gz
```

Example output:
```
Private inputs: 1
Public inputs:  3
Return values:  0
Opcodes:        1
Witnesses:      5
Constraints:    1
([0, 1, 0, 0, 0] x [1, 1, 2, 3, 5]ᵀ) * ([0, 0, 1, 0, 0] x [1, 1, 2, 3, 5]ᵀ) = ([0, 0, 0, -1, 1] x [1, 1, 2, 3, 5]ᵀ)
✅ All constraints are valid.
```
