use {
    bn254_multiplier_codegen::{karatsuba, schoolbook, simd},
    hla::builder::{build_includable, Interleaving},
    std::path::Path,
};

fn main() {
    let path = Path::new("./src/aarch64/montgomery_interleaved_3.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::single(karatsuba::MUL),
                Interleaving::single(simd::setup_single_step),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_interleaved_4.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::seq(vec![
                    schoolbook::setup_single_step,
                    schoolbook::setup_single_step,
                ]),
                Interleaving::single(simd::setup_single_step),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_square_interleaved_3.s");
    if !path.exists() {
        build_includable(
            path,
            Interleaving::par(
                Interleaving::single(schoolbook::setup_square_single_step),
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
                    schoolbook::setup_square_single_step,
                    schoolbook::setup_square_single_step,
                ]),
                Interleaving::single(simd::setup_square_single_step),
            ),
        );
    }
    let path = Path::new("./src/aarch64/montgomery_mul.s");
    if !path.exists() {
        build_includable(path, Interleaving::single(karatsuba::MUL));
    }
}
