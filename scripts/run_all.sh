# Run this in the `noir-r1cs` directory!

shopt -s nullglob
cargo build --release --bin circuit_stats
for file in noir-passport-examples/*.json; do
  echo "$file"
  ./target/release/circuit_stats "$file" noir-examples/basic/target/basic.gz
done
