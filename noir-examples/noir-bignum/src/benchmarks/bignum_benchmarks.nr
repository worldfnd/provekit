use crate::bignum::BigNum;

comptime fn make_bench(_m: Module, N: u32, MOD_BITS: u32, params: Quoted) -> Quoted {
    let module_name = _m.name();
    let add_bench_name = f"add_{module_name}".quoted_contents();
    let sub_bench_name = f"sub_{module_name}".quoted_contents();
    let mul_bench_name = f"mul_{module_name}".quoted_contents();
    let div_bench_name = f"div_{module_name}".quoted_contents();
    let udiv_mod_bench_name = f"udiv_mod_{module_name}".quoted_contents();
    let udiv_bench_name = f"udiv_{module_name}".quoted_contents();
    let from_field_bench_name = f"from_field_{module_name}".quoted_contents();
    let validate_in_field_bench_name = f"validate_in_field_{module_name}".quoted_contents();
    let evaluate_quadratic_expression_3_elements_bench_name =
        f"evaluate_quadratic_expression_3_elements_{module_name}".quoted_contents();
    let evaluate_quadratic_expression_12_elements_bench_name =
        f"evaluate_quadratic_expression_12_elements_{module_name}".quoted_contents();

    let BigNum = quote { crate::bignum::BigNum };
    let BigNumTrait = quote { crate::bignum::BigNumTrait };

    quote {
        #[export]
        fn $add_bench_name(a: $BigNum<$N, $MOD_BITS, $params>, b: $BigNum<$N, $MOD_BITS, $params>) -> $BigNum<$N, $MOD_BITS, $params> {
            a + b
        }

        #[export] 
        fn $sub_bench_name(a: $BigNum<$N, $MOD_BITS, $params>, b: $BigNum<$N, $MOD_BITS, $params>) -> $BigNum<$N, $MOD_BITS, $params> {
            a - b
        }

        #[export]
        fn $mul_bench_name(a: $BigNum<$N, $MOD_BITS, $params>, b: $BigNum<$N, $MOD_BITS, $params>) -> $BigNum<$N, $MOD_BITS, $params> {
            a * b
        }

        #[export]
        fn $div_bench_name(a: $BigNum<$N, $MOD_BITS, $params>, b: $BigNum<$N, $MOD_BITS, $params>) -> $BigNum<$N, $MOD_BITS, $params> {
            a / b
        }

        #[export]  
        fn $udiv_mod_bench_name(a: $BigNum<$N, $MOD_BITS, $params>, b: $BigNum<$N, $MOD_BITS, $params>) -> ($BigNum<$N, $MOD_BITS, $params>, $BigNum<$N, $MOD_BITS, $params>) {
            $BigNumTrait::udiv_mod(a, b)
        }

        #[export]
        fn $udiv_bench_name(a: $BigNum<$N, $MOD_BITS, $params>, b: $BigNum<$N, $MOD_BITS, $params>) -> $BigNum<$N, $MOD_BITS, $params> {
            $BigNumTrait::udiv(a, b)
        }
        
        #[export]
        fn $from_field_bench_name(a: Field) -> $BigNum<$N, $MOD_BITS, $params> {
            $BigNum::from(a)
        }

        #[export]
        fn $validate_in_field_bench_name(a: $BigNum<$N, $MOD_BITS, $params>) {
            $BigNumTrait::validate_in_field(a)
        }        

        #[export]
        fn $evaluate_quadratic_expression_3_elements_bench_name(
            lhs: [[$BigNum<$N, $MOD_BITS, $params>; 3]; 3],
            lhs_flags: [[bool; 3]; 3],
            rhs: [[$BigNum<$N, $MOD_BITS, $params>; 3]; 3],
            rhs_flags: [[bool; 3]; 3],
            add: [$BigNum<$N, $MOD_BITS, $params>; 3],
            add_flags: [bool; 3],
        ) {
            $BigNumTrait::evaluate_quadratic_expression(lhs, lhs_flags, rhs, rhs_flags, add, add_flags)
        }

        #[export]
        fn $evaluate_quadratic_expression_12_elements_bench_name(
            lhs: [[$BigNum<$N, $MOD_BITS, $params>; 3]; 12],
            lhs_flags: [[bool; 3]; 12],
            rhs: [[$BigNum<$N, $MOD_BITS, $params>; 3]; 12],
            rhs_flags: [[bool; 3]; 12],
            add: [$BigNum<$N, $MOD_BITS, $params>; 3],
            add_flags: [bool; 3],
        ) {
            $BigNumTrait::evaluate_quadratic_expression(lhs, lhs_flags, rhs, rhs_flags, add, add_flags)
        }
        
    }
}

// the types we will be benchmarking
// type BN254Fq
// type U256
// type BLS12_381Fq
// type U2048
#[make_bench(3, 254, quote { BN254_Fq_Params })]
pub mod BN254_Fq_Bench {
    use crate::fields::bn254Fq::BN254_Fq_Params;
}

#[make_bench(3, 257, quote { U256Params })]
pub mod U256_Bench {
    use crate::fields::U256::U256Params;
}

#[make_bench(4, 381, quote { BLS12_381_Fq_Params })]
pub mod BLS12_381Fq_Bench {

    use crate::fields::bls12_381Fq::BLS12_381_Fq_Params;
}

#[make_bench(18, 2049, quote { U2048Params })]
pub mod U2048_Bench {
    use crate::fields::U2048::U2048Params;
}
