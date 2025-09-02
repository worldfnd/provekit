fn main(switch: Field, mut mem: [Field; 2], addr0: u32, addr1: u32) -> pub Field {
    if switch == 0 {
        mem[addr0] = 2;
    }
    mem[addr1]
}
