fn main(mut mem: [Field; 3], addr0: u32, addr1: u32, addr: u32) -> pub Field {
    let z = mem[addr0];
    mem[addr0] = mem[addr1];
    mem[addr1] = z;
    mem[addr]
}
