nargo compile
nargo check
nargo execute my-witness
bb prove -b ./target/zkchase.json -w ./target/my-witness.gz -o ./target/proof
echo "✅ Proof generated at ./target/proof"
bb write_vk -b ./target/zkchase.json -o ./target/vk
bb verify -k ./target/vk -p ./target/proof
echo "✅ Verified the proof at ./target/proof"
