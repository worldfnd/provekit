fn main(mem: [Field; 6], addr0: Field, addr1: Field, addr2: Field) -> pub Field {
    mem[addr0] * mem[addr1]
        + mem[addr2]
        + mem[addr0]
        + mem[addr0]
        + mem[addr0] * mem[addr1] * mem[addr1] * mem[addr1]
        + mem[addr2] * mem[addr2]
        + mem[addr2] * mem[addr2]
}
