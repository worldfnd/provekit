use super::montgomery::MontgomeryPoint;

/// Returns [1G, 2G, 3G, 4G, 5G, 6G, 7G, 8G] in Montgomery form
pub fn generator_window_table() -> [MontgomeryPoint; 8] {
    [
        MontgomeryPoint {
            u: 0x0fbc9ac10c16d45d4eacdd6489fa006480b17a811cdba46922896085f89faaf6,
            v: 0x203a710160811d5c07ebaeb8fe1d9ce201c66b970d66f18d0d2b264c195309aa,
        }, // 1G
        MontgomeryPoint {
            u: 0x1d3f81272fad655832eba10d787590f127db9b237de125a4896a77e8e431acac,
            v: 0x189dec24f83c74e3a405e2281e7a35686dcbe4a04289b9332552453fbcc4f88e,
        }, // 2G
        MontgomeryPoint {
            u: 0x226a97c4351979237a40e63c1f60a99c96c6a56e70bc05056eeb44b9421bcb28,
            v: 0x0ebf010a901932c8274d2dc69adf03a97b6f00d46e04eef7e25ec3a3d6a371b6,
        }, // 3G
        MontgomeryPoint {
            u: 0x246594a9dd2551feb3c449c51fee3c6c1f0f497b0b04d1c1c41936fc8c099387,
            v: 0x1926506d186ac821b2304fb7214754c79a4f417f03ba520fd28b96b900a68680,
        }, // 4G
        MontgomeryPoint {
            u: 0x2d5961c29f9540736275bd25a11391dd0079e3f2717538045fb98aee55209cd4,
            v: 0x128acbbccc72b258569c428007c0e2c62659f5e7fd49614f9fbfb1be878dec87,
        }, // 5G
        MontgomeryPoint {
            u: 0x1a242868cf638a1873e859e4a863ce6018136d1516f9c6ab92b54954eee2f7ab,
            v: 0x1dcb75a13408518f379d69c5ef72118c4b35d42249f35bc683b1649a658816c5,
        }, // 6G
        MontgomeryPoint {
            u: 0x27adcdd94a3060ea05348b7d9305c5fa7dce3678907c3f1955631d62cea0d822,
            v: 0x06b0231d7acb5ecabf47de20e39f2d9a55f950ff9e484c1c839cc927abf47342,
        }, // 7G
        MontgomeryPoint {
            u: 0x1109c2ba4fc20e6ec96c86477291a8247b2716f3b88f625c2a900ade224d0c0a,
            v: 0x1ea6710ce10503dff8e86838ec5ab7da115123963330c4546e525da9e1d0526d,
        }, // 8G
    ]
}

/// Generate precomputed table for 3-bit windows
/// Returns [1B, 2B, 3B, 4B, 5B, 6B, 7B, 8B] in Montgomery form
pub fn generate_window_table(base: MontgomeryPoint) -> [MontgomeryPoint; 8] {
    let mut table: [MontgomeryPoint; 8] = [base; 8];

    // 1B = base (already assigned)

    // 2B = double(1B)
    table[1] = base.double();

    // 3B = 2B + 1B
    table[2] = table[1].add(table[0]);

    // 4B = 3B + 1B
    table[3] = table[1].double();

    // 5B = 4B + 1B
    table[4] = table[3].add(table[0]);

    // 6B = 5B + 1B
    table[5] = table[2].double();

    // 7B = 6B + 1B
    table[6] = table[5].add(table[0]);

    // 8B = 7B + 1B
    table[7] = table[3].double();

    table
}

pub fn select_from_window(bits: [u1; 3], table: [MontgomeryPoint; 8]) -> MontgomeryPoint {
    let b0 = bits[0] as Field;
    let b1 = bits[1] as Field;
    let b2 = bits[2] as Field;

    let lower_half = mux_point(b2, table[4], table[0]);
    let upper_half = mux_point(b2, table[5], table[1]);
    let mid_lower = mux_point(b2, table[6], table[2]);
    let mid_upper = mux_point(b2, table[7], table[3]);

    let first_pair = mux_point(b1, mid_lower, lower_half);
    let second_pair = mux_point(b1, mid_upper, upper_half);

    mux_point(b0, second_pair, first_pair) // b0=0->first_pair, b0=1->second_pair
}

fn mux_point(
    selector: Field,
    point_a: MontgomeryPoint,
    point_b: MontgomeryPoint,
) -> MontgomeryPoint {
    MontgomeryPoint {
        u: selector * point_a.u + (1 - selector) * point_b.u,
        v: selector * point_a.v + (1 - selector) * point_b.v,
    }
}

#[test]
fn test_window_selection() {
    let g = crate::BabyJubJubPoint::generator();
    let table = generate_window_table(g.to_montgomery());

    let bits: [u1; 3] = [1, 0, 1];
    let selected = select_from_window(bits, table);

    assert(selected.u == table[5].u, "Window selection u mismatch for bits [1,0,1] -> 6B"); // 6B is at index 5
    assert(selected.v == table[5].v, "Window selection v mismatch for bits [1,0,1] -> 6B");

    // Test window = 0 (bits = [0, 0, 0])
    // Window value 0 should return table[0] = 1B (compensation: 0 -> 1B)
    let zero_bits: [u1; 3] = [0, 0, 0];
    let selected_zero = select_from_window(zero_bits, table);

    assert(selected_zero.u == table[0].u, "Window selection u mismatch for bits [0,0,0] -> 1B"); // 1B is at index 0
    assert(selected_zero.v == table[0].v, "Window selection v mismatch for bits [0,0,0] -> 1B");
}

#[test]
fn test_generator_window_table() {
    // Test that the precomputed generator table matches the dynamically computed one
    let g = crate::BabyJubJubPoint::generator();
    let g_mont = g.to_montgomery();

    let precomputed_table = generator_window_table();
    let dynamic_table = generate_window_table(g_mont);

    // Compare all entries
    for i in 0..8 {
        assert(
            precomputed_table[i].u == dynamic_table[i].u,
            "Precomputed vs dynamic table u mismatch at index",
        );
        assert(
            precomputed_table[i].v == dynamic_table[i].v,
            "Precomputed vs dynamic table v mismatch at index",
        );
    }
}

#[test]
fn test_generator_window_table_values() {
    let g = crate::BabyJubJubPoint::generator();
    let table = generator_window_table();

    let g2 = g.double();
    let g4 = g2.double();
    let g8 = g4.double();

    let g2_mont = g2.to_montgomery();
    let g4_mont = g4.to_montgomery();
    let g8_mont = g8.to_montgomery();

    // Verify 2G, 4G, 8G
    assert(table[1].u == g2_mont.u, "2G u mismatch in generator table");
    assert(table[1].v == g2_mont.v, "2G v mismatch in generator table");

    assert(table[3].u == g4_mont.u, "4G u mismatch in generator table");
    assert(table[3].v == g4_mont.v, "4G v mismatch in generator table");

    assert(table[7].u == g8_mont.u, "8G u mismatch in generator table");
    assert(table[7].v == g8_mont.v, "8G v mismatch in generator table");
}
