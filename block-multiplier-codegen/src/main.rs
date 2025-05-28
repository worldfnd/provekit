use {
    block_multiplier_codegen::{
        scalar::{setup_montgomery_single_step, setup_montgomery_squaring_single_step},
        simd::{setup_single_step_simd, setup_single_step_squaring_simd},
    },
    hla::builder::{Interleaving, build_includable},
};

fn main() {
    build_includable(
        "./asm/montgomery_interleaved_3.s",
        Interleaving::par(
            Interleaving::single(setup_montgomery_single_step),
            Interleaving::single(setup_single_step_simd),
        ),
    );
    build_includable(
        "./asm/montgomery_square_interleaved_3.s",
        Interleaving::par(
            Interleaving::single(setup_montgomery_squaring_single_step),
            Interleaving::single(setup_single_step_squaring_simd),
        ),
    );
    build_includable(
        "./asm/montgomery_interleaved_4.s",
        Interleaving::par(
            Interleaving::seq(vec![
                setup_montgomery_single_step,
                setup_montgomery_single_step,
            ]),
            Interleaving::single(setup_single_step_simd),
        ),
    );
    build_includable(
        "./asm/montgomery_square_interleaved_4.s",
        Interleaving::par(
            Interleaving::seq(vec![
                setup_montgomery_squaring_single_step,
                setup_montgomery_squaring_single_step,
            ]),
            Interleaving::single(setup_single_step_squaring_simd),
        ),
    );
    build_includable(
        "./asm/montgomery.s",
        Interleaving::single(setup_montgomery_single_step),
    );
    build_includable(
        "./asm/montgomery_square.s",
        Interleaving::single(setup_montgomery_squaring_single_step),
    );
}
