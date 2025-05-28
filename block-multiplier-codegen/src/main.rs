use {
    block_multiplier_codegen::{
        scalar::setup_montgomery_single_step, simd::setup_single_step_simd,
    },
    hla::builder::{Interleaving, build_inline},
};

fn main() {
    build_inline(
        "./asm/montgomery_interleaved_3.s",
        Interleaving::par(
            Interleaving::single(setup_montgomery_single_step),
            Interleaving::single(setup_single_step_simd),
        ),
    );
    build_inline(
        "./asm/montgomery_interleaved_4.s",
        Interleaving::par(
            Interleaving::seq(vec![
                setup_montgomery_single_step,
                setup_montgomery_single_step,
            ]),
            Interleaving::single(setup_single_step_simd),
        ),
    );
    build_inline(
        "./asm/montgomery.s",
        Interleaving::single(setup_montgomery_single_step),
    );
}
