use {
    block_multiplier_codegen::{scalar, simd},
    hla::builder::{Interleaving, build_includable},
    std::path::Path,
};

fn main() {
    let path = Path::new("./src/aarch64/montgomery_interleaved_3.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::single(scalar::setup_single_step),
                Interleaving::single(simd::setup_single_step),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_interleaved_4.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::seq(vec![scalar::setup_single_step, scalar::setup_single_step]),
                Interleaving::single(simd::setup_single_step),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_square_interleaved_3.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::single(scalar::setup_square_single_step),
                Interleaving::single(simd::setup_square_single_step),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_square_interleaved_4.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::seq(vec![
                    scalar::setup_square_single_step,
                    scalar::setup_square_single_step,
                ]),
                Interleaving::single(simd::setup_square_single_step),
            ),
        );
    }
}
