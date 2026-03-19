use {ark_bn254::Fr, std::any::TypeId, whir::algebra::fields::Field256};

fn main() {
    println!("Fr: {:?}", TypeId::of::<Fr>());
    println!("Field256: {:?}", TypeId::of::<Field256>())
}
