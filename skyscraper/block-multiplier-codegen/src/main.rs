use {
    block_multiplier_codegen::{scalar, simd},
    hla::builder::{build_includable, Interleaving},
};

fn main() {
    build_includable(
        "./asm/montgomery_interleaved_3.s",
        Interleaving::par(
            Interleaving::single(scalar::setup_single_step),
            Interleaving::single(simd::setup_single_step),
        ),
    );
    build_includable(
        "./asm/montgomery_square_interleaved_3.s",
        Interleaving::par(
            Interleaving::single(scalar::setup_square_single_step),
            Interleaving::single(simd::setup_square_single_step),
        ),
    );
    build_includable(
        "./asm/montgomery_square_log_interleaved_3.s",
        Interleaving::par(
            Interleaving::single(scalar::setup_square_log_jump),
            Interleaving::single(simd::setup_square_single_step),
        ),
    );
    build_includable(
        "./asm/montgomery_interleaved_4.s",
        Interleaving::par(
            Interleaving::seq(vec![scalar::setup_single_step, scalar::setup_single_step]),
            Interleaving::single(simd::setup_single_step),
        ),
    );
    build_includable(
        "./asm/montgomery_square_interleaved_4.s",
        Interleaving::par(
            Interleaving::seq(vec![
                scalar::setup_square_single_step,
                scalar::setup_square_single_step,
            ]),
            Interleaving::single(simd::setup_square_single_step),
        ),
    );
    build_includable(
        "./asm/montgomery_square_log_interleaved_4.s",
        Interleaving::par(
            Interleaving::seq(vec![
                scalar::setup_square_log_jump,
                scalar::setup_square_log_jump,
            ]),
            Interleaving::single(simd::setup_square_single_step),
        ),
    );
    build_includable(
        "./asm/montgomery.s",
        Interleaving::single(scalar::setup_single_step),
    );
    build_includable(
        "./asm/montgomery_square.s",
        Interleaving::single(scalar::setup_square_single_step),
    );
    build_includable(
        "./asm/montgomery_log_jump.s",
        Interleaving::single(scalar::setup_log_jump),
    );
}
