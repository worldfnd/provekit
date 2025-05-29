fn main(mut dg1: [u8; 5]) {
    // dg1 = [ 42, 19, ... ];
    if dg1[0] > 40 {
        dg1[1] += 1;
    }
    assert_eq([dg1[0], dg1[1]], [42, 20]);
}