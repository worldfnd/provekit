use {
    block_multiplier_codegen::{
        scalar::{setup_montgomery_single_step, setup_montgomery_squaring_single_step},
        simd::{setup_single_step_simd, setup_single_step_squaring_simd},
    },
    hla::builder::{Interleaving, build_includable},
    std::path::Path,
};

fn main() {
    let path = Path::new("./src/aarch64/montgomery_interleaved_3.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::single(setup_montgomery_single_step),
                Interleaving::single(setup_single_step_simd),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_interleaved_4.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::seq(vec![
                    setup_montgomery_single_step,
                    setup_montgomery_single_step,
                ]),
                Interleaving::single(setup_single_step_simd),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_square_interleaved_3.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::single(setup_montgomery_squaring_single_step),
                Interleaving::single(setup_single_step_squaring_simd),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_square_interleaved_4.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::seq(vec![
                    setup_montgomery_squaring_single_step,
                    setup_montgomery_squaring_single_step,
                ]),
                Interleaving::single(setup_single_step_squaring_simd),
            ),
        );
    }
}
