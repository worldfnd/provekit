fn main(switch: Field, mut mem: [Field; 2], addr0: Field, addr1: Field) -> pub Field {
	if switch == 0 {
		mem[addr0] = 2;
	}
	mem[addr1]
}
