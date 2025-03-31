# Run this in the `noir-r1cs` directory!

for file in noir-passport-examples/*.json; do
  echo "$file"
  cargo run --bin circuit_stats -- "$file" noir-examples/basic/target/basic.gz
done