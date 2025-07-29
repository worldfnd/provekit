fn main(mem: [Field; 6], addr0: u32, addr1: u32, addr2: u32) -> pub Field {
    mem[addr0] * mem[addr1]
        + mem[addr2]
        + mem[addr0]
        + mem[addr0]
        + mem[addr0] * mem[addr1] * mem[addr1] * mem[addr1]
        + mem[addr2] * mem[addr2]
        + mem[addr2] * mem[addr2]
}
