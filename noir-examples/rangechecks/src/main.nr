fn main(x: Field) {
    for i in 0..10000 {
        let r = x + i as Field;
        r.assert_max_bit_size::<32>();
    }
}

