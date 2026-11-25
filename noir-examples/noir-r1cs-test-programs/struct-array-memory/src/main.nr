struct Pair {
    a: Field,
    b: Field,
}

fn main(
    pairs: [Pair; 4],
    mut scratch: [Pair; 4],
    rom_read: u32,
    ram_write: u32,
    ram_read: u32,
) -> pub Field {
    let from_rom = pairs[rom_read];
    scratch[ram_write] = from_rom;
    let from_ram = scratch[ram_read];
    from_rom.a * from_ram.b + from_ram.a
}
