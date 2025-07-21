use crate::fields::{
    bls12_377Fq::BLS12_377_Fq, bls12_377Fr::BLS12_377_Fr, bls12_381Fq::BLS12_381_Fq,
    bls12_381Fr::BLS12_381_Fr, bn254Fq::BN254_Fq, U2048::U2048, U256::U256,
};

comptime fn make_bench(m: Module, params: Quoted) -> Quoted {
    let module_name = m.name();
    let add_bench_name = f"add_{module_name}".quoted_contents();
    let sub_bench_name = f"sub_{module_name}".quoted_contents();
    let mul_bench_name = f"mul_{module_name}".quoted_contents();
    let div_bench_name = f"div_{module_name}".quoted_contents();
    let udiv_mod_bench_name = f"udiv_mod_{module_name}".quoted_contents();
    let udiv_bench_name = f"udiv_{module_name}".quoted_contents();
    let validate_in_field_bench_name = f"validate_in_field_{module_name}".quoted_contents();
    let evaluate_quadratic_expression_3_elements_bench_name =
        f"evaluate_quadratic_expression_3_elements_{module_name}".quoted_contents();
    let evaluate_quadratic_expression_12_elements_bench_name =
        f"evaluate_quadratic_expression_12_elements_{module_name}".quoted_contents();
    // let to_be_bytes_bench_name = f"to_be_bytes_{module_name}".quoted_contents();
    // let from_be_bytes_bench_name = f"from_be_bytes_{module_name}".quoted_contents();
    // let to_le_bytes_bench_name = f"to_le_bytes_{module_name}".quoted_contents();
    // let from_le_bytes_bench_name = f"from_le_bytes_{module_name}".quoted_contents();
    let BigNum = quote { crate::bignum::BigNum };
    let from_field_bench_name = f"from_field_{module_name}".quoted_contents();
    let typ = params.as_type();

    quote {
        #[export]
        fn $add_bench_name(a: $typ, b: $typ) -> $typ {
            a + b
        }

        #[export] 
        fn $sub_bench_name(a: $typ, b: $typ) -> $typ {
            a - b
        }

        #[export]
        fn $mul_bench_name(a: $typ, b: $typ) -> $typ {
            a * b
        }

        #[export]
        fn $div_bench_name(a: $typ, b: $typ) -> $typ {
            a / b
        }

        #[export]  
        fn $udiv_mod_bench_name(a: $typ, b: $typ) -> ($typ, $typ) {
            $BigNum::udiv_mod(a, b)
        }

        #[export]
        fn $udiv_bench_name(a: $typ, b: $typ) -> $typ {
            $BigNum::udiv(a, b)
        }

        #[export]
        fn $validate_in_field_bench_name(a: $typ) {
            $BigNum::validate_in_field(a)
        }        

        #[export]
        fn $evaluate_quadratic_expression_3_elements_bench_name(
            lhs: [[$typ; 3]; 3],
            lhs_flags: [[bool; 3]; 3],
            rhs: [[$typ; 3]; 3],
            rhs_flags: [[bool; 3]; 3],
            add: [$typ; 3],
            add_flags: [bool; 3],
        ) {
            crate::bignum::evaluate_quadratic_expression(lhs, lhs_flags, rhs, rhs_flags, add, add_flags)
        }

        #[export]
        fn $evaluate_quadratic_expression_12_elements_bench_name(
            lhs: [[$typ; 3]; 12],
            lhs_flags: [[bool; 3]; 12],
            rhs: [[$typ; 3]; 12],
            rhs_flags: [[bool; 3]; 12],
            add: [$typ; 3],
            add_flags: [bool; 3],
        ) {
            crate::bignum::evaluate_quadratic_expression(lhs, lhs_flags, rhs, rhs_flags, add, add_flags)
        }
        
        #[export]
        fn $from_field_bench_name(a: Field) -> $typ {
            $typ::from(a)
        }

        // #[export]
        // fn $to_be_bytes_bench_name(a: $typ) -> [u8; ($MOD_BITS+7) / 8] {
        //     $BigNum::to_be_bytes(a)
        // }

        // #[export]
        // fn $from_be_bytes_bench_name(a: [u8; ($MOD_BITS+7) / 8]) -> $typ {
        //     $BigNum::from_be_bytes(a)
        // }

        // #[export]
        // fn $to_le_bytes_bench_name(a: $typ) -> [u8; ($MOD_BITS+7) / 8] {
        //     $BigNum::to_le_bytes(a)
        // }

        // #[export]
        // fn $from_le_bytes_bench_name(a: [u8; ($MOD_BITS+7) / 8]) -> $typ {
        //     $BigNum::from_le_bytes(a)
        // }      
    }
}

// the types we will be benchmarking
// type BN254Fq
// type U256
// type BLS12_381Fq
// type U2048
#[make_bench(quote { BN254_Fq })]
mod BN254_Fq_Bench {}

#[make_bench(quote { U256 })]
mod U256_Bench {}

#[make_bench(quote { BLS12_381_Fq })]
mod BLS12_381Fq_Bench {}

#[make_bench(quote { BLS12_381_Fr })]
mod BLS12_381Fr_Bench {}

#[make_bench(quote { BLS12_377_Fr })]
mod BLS12_377Fr_Bench {}

#[make_bench(quote { BLS12_377_Fq })]
mod BLS12_377Fq_Bench {}
#[make_bench(quote { U2048 })]
mod U2048_Bench {}
