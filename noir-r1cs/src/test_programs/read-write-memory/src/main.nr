fn main(mut mem: [Field; 3], addr0: Field, addr1: Field, addr: Field) -> pub Field {
	let z = mem[addr0];
	mem[addr0] = mem[addr1];
	mem[addr1] = z;
	mem[addr]
}
