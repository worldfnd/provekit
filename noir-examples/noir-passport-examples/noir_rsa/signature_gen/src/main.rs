use num_bigint::BigUint;
use rsa::pkcs1v15::Signature;
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::Keypair;
use signature::RandomizedSignerMut;
use std::env;
use toml::Value;

use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha1::Sha1;

use clap::{App, Arg};

use noir_bignum_paramgen::{
    bn_limbs, compute_barrett_reduction_parameter, split_into_120_bit_limbs,
};

fn format_limbs_as_hex(limbs: &Vec<BigUint>) -> String {
    limbs
        .iter()
        .map(|a| format!("0x{:x}", a))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_limbs_as_toml_value(limbs: &Vec<BigUint>) -> Vec<Value> {
    limbs
        .iter()
        .map(|a| Value::String(format!("0x{:x}", a)))
        .collect()
}

fn generate_2048_bit_signature_parameters(msg: &str, as_toml: bool, exponent: u32, pss: bool) {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let hashed_message = hasher.finalize();

    let hashed_as_bytes = hashed_message
        .iter()
        .map(|&b| b.to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let bits: usize = 2048;
    let priv_key: RsaPrivateKey =
        RsaPrivateKey::new_with_exp(&mut rng, bits, &BigUint::from(exponent))
            .expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();

    let sig_bytes = if pss {
        let mut signing_key = rsa::pss::BlindedSigningKey::<Sha256>::new(priv_key);
        let sig = signing_key.sign_with_rng(&mut rng, msg.as_bytes());
        sig.to_vec()
    } else {
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
        signing_key.sign(msg.as_bytes()).to_vec()
    };

    let sig_uint: BigUint = BigUint::from_bytes_be(&sig_bytes);

    let sig_str = bn_limbs(sig_uint.clone(), 2048);

    let modulus_limbs: Vec<BigUint> = split_into_120_bit_limbs(&pub_key.n().clone(), 2048);
    let redc_limbs = split_into_120_bit_limbs(
        &compute_barrett_reduction_parameter(&pub_key.n().clone()),
        2048,
    );

    if as_toml {
        let sig_limbs = split_into_120_bit_limbs(&sig_uint.clone(), 2048);

        println!("hash = [{}]", hashed_as_bytes);
        println!(
            "modulus_limbs = {}",
            Value::Array(format_limbs_as_toml_value(&modulus_limbs))
        );
        println!(
            "redc_limbs = {}",
            Value::Array(format_limbs_as_toml_value(&redc_limbs))
        );
        println!(
            "signature_limbs = {}",
            Value::Array(format_limbs_as_toml_value(&sig_limbs))
        );
    } else {
        println!("let hash: [u8; 32] = [{}];", hashed_as_bytes);
        println!(
            "let params: BigNumParams<18, 2048> = BigNumParams::new(\n\tfalse,\n\t[{}],\n\t[{}]\n);",
            format_limbs_as_hex(&modulus_limbs),
            format_limbs_as_hex(&redc_limbs)
        );
        println!(
            "let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum::from_array(\n\tparams,\n\tlimbs: {}\n);",
            sig_str.as_str()
        );
    }
}

fn generate_1024_bit_signature_parameters(msg: &str, as_toml: bool, exponent: u32) {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let hashed_message = hasher.finalize();

    let hashed_as_bytes = hashed_message
        .iter()
        .map(|&b| b.to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let bits: usize = 1024;
    let priv_key: RsaPrivateKey =
        RsaPrivateKey::new_with_exp(&mut rng, bits, &BigUint::from(exponent))
            .expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();

    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
    let sig: Vec<u8> = signing_key.sign(msg.as_bytes()).to_vec();

    let sig_bytes = &Signature::try_from(sig.as_slice()).unwrap().to_bytes();

    let sig_uint: BigUint = BigUint::from_bytes_be(sig_bytes);

    let sig_str = bn_limbs(sig_uint.clone(), 1024);

    let modulus_limbs: Vec<BigUint> = split_into_120_bit_limbs(&pub_key.n().clone(), 1024);
    let redc_limbs = split_into_120_bit_limbs(
        &compute_barrett_reduction_parameter(&pub_key.n().clone()),
        1024,
    );

    if as_toml {
        let sig_limbs = split_into_120_bit_limbs(&sig_uint.clone(), 1024);

        println!("hash = [{}]", hashed_as_bytes);
        println!(
            "modulus_limbs = {}",
            Value::Array(format_limbs_as_toml_value(&modulus_limbs))
        );
        println!(
            "redc_limbs = {}",
            Value::Array(format_limbs_as_toml_value(&redc_limbs))
        );
        println!(
            "signature_limbs = {}",
            Value::Array(format_limbs_as_toml_value(&sig_limbs))
        );
    } else {
        println!(
            "let params: BigNumParams<9, 1024> = BigNumParams::new(\n\tfalse,\n\t[{}],\n\t[{}]\n);",
            format_limbs_as_hex(&modulus_limbs),
            format_limbs_as_hex(&redc_limbs)
        );
        println!(
            "let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum::from_array(\n\tparams,\n\tlimbs: {}\n);",
            sig_str.as_str()
        );
    }
}

fn main() {
    let matches = App::new("RSA Signature Generator")
        .arg(
            Arg::with_name("msg")
                .short("m")
                .long("msg")
                .takes_value(true)
                .help("Message to sign")
                .required(true),
        )
        .arg(
            Arg::with_name("toml")
                .short("t")
                .long("toml")
                .help("Print output in TOML format"),
        )
        .arg(
            Arg::with_name("exponent")
                .short("e")
                .long("exponent")
                .takes_value(true)
                .help("Exponent to use for the key")
                .default_value("65537"),
        )
        .arg(
            Arg::with_name("bits")
                .short("b")
                .long("bits")
                .takes_value(true)
                .help("Number of bits of RSA signature (1024 or 2048")
                .default_value("2048"),
        )
        .arg(
            Arg::with_name("pss")
                .short("p")
                .long("pss")
                .help("Use RSA PSS"),
        )
        .get_matches();

    let msg = matches.value_of("msg").unwrap();
    let as_toml = matches.is_present("toml");
    let e: u32 = matches.value_of("exponent").unwrap().parse().unwrap();
    let b: u32 = matches.value_of("bits").unwrap().parse().unwrap();
    assert!(
        b == 1024 || b == 2048,
        "Number of bits of RSA signature can only be 1024 or 2048"
    );
    let pss = matches.is_present("pss");

    if b == 1024 {
        generate_1024_bit_signature_parameters(msg, as_toml, e);
    } else {
        generate_2048_bit_signature_parameters(msg, as_toml, e, pss);
    }
}

/*fn test_signature_generation_impl() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();
    let text: &str = "hello world";
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
    let sig: Vec<u8> = signing_key.sign(text.as_bytes()).to_vec();
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

    let result = verifying_key.verify(
        text.as_bytes(),
        &Signature::try_from(sig.as_slice()).unwrap(),
    );
    if b == 1024 {
        generate_1024_bit_signature_parameters(msg, as_toml, e);
    } else {
        generate_2048_bit_signature_parameters(msg, as_toml, e, pss);
    }
}*/

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rsa::pkcs1v15::Signature;
    use rsa::signature::{Signer, Verifier};
    use rsa::{pkcs1v15::VerifyingKey, RsaPrivateKey, RsaPublicKey};
    use sha2::{Sha256, Sha384, Sha512};

    #[test]
    fn test_signature_generation() {
        let mut rng = thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key: RsaPublicKey = priv_key.clone().into();
        let text: &str = "hello world";
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
        let sig: Vec<u8> = signing_key.sign(text.as_bytes()).to_vec();
        let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

        let result = verifying_key.verify(
            text.as_bytes(),
            &Signature::try_from(sig.as_slice()).unwrap(),
        );
        result.expect("failed to verify");
    }

    #[test]
    fn test_signature_generation_sha384() {
        let mut rng = thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key: RsaPublicKey = priv_key.clone().into();
        let text: &str = "hello world";
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha384>::new(priv_key);
        let sig: Vec<u8> = signing_key.sign(text.as_bytes()).to_vec();
        let verifying_key = VerifyingKey::<Sha384>::new(pub_key);

        let result = verifying_key.verify(
            text.as_bytes(),
            &Signature::try_from(sig.as_slice()).unwrap(),
        );
        result.expect("failed to verify");
    }

    #[test]
    fn test_signature_generation_sha512() {
       let mut rng = thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key: RsaPublicKey = priv_key.clone().into();
        let text: &str = "hello world";
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha384>::new(priv_key);
        let sig: Vec<u8> = signing_key.sign(text.as_bytes()).to_vec();
        let verifying_key = VerifyingKey::<Sha384>::new(pub_key);

        let result = verifying_key.verify(
            text.as_bytes(),
            &Signature::try_from(sig.as_slice()).unwrap(),
        );
        result.expect("failed to verify");
    }
}

