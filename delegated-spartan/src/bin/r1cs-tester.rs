use {
    ark_bn254::Fr,
    ark_ff::Field,
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate},
    rayon::iter::repeatn,
    serde::{Deserialize, Serialize},
    std::{fs::File, str::FromStr},
};

#[derive(Deserialize)]
struct R1CS {
    num_public:      usize,
    num_variables:   usize,
    num_constraints: usize,
    a:               SparseMatrix,
    b:               SparseMatrix,
    c:               SparseMatrix,
    #[serde(deserialize_with = "ark_de_vv")]
    witnesses:       Vec<Vec<Fr>>,
}

type SparseMatrix = Vec<SpartMatrixEntry>;

#[derive(Deserialize)]
struct SpartMatrixEntry {
    constraint: usize,
    signal:     usize,
    #[serde(deserialize_with = "ark_de")]
    value:      Fr,
}

fn ark_de<'de, D>(data: D) -> Result<Fr, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(data)?;
    Ok(Fr::from_str(&s).unwrap())
}

fn ark_de_vv<'de, D>(data: D) -> Result<Vec<Vec<Fr>>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<Vec<String>> = serde::de::Deserialize::deserialize(data)?;
    Ok(s.iter()
        .map(|s| s.iter().map(|s| Fr::from_str(s).unwrap()).collect())
        .collect())
}

fn main() {
    println!("Parsing JSON...");
    // let file = File::open("disclose_wrencher.json").unwrap();
    let file = File::open("rsa_verifier_65537_2048_wrencher.json").unwrap();
    let r1cs: R1CS = serde_json::from_reader(file).unwrap();
    println!("done.");

    println!("num_public: {}", r1cs.num_public);
    println!("num_variables: {}", r1cs.num_variables);
    println!("num_constraints: {}", r1cs.num_constraints);

    println!(
        "max a.signal {}",
        r1cs.a.iter().map(|e| e.signal).max().unwrap()
    );
    println!(
        "max b.signal {}",
        r1cs.b.iter().map(|e| e.signal).max().unwrap()
    );
    println!(
        "max c.signal {}",
        r1cs.c.iter().map(|e| e.signal).max().unwrap()
    );
    println!(
        "max a.constraint {}",
        r1cs.a.iter().map(|e| e.constraint).max().unwrap()
    );
    println!(
        "max b.constraint {}",
        r1cs.b.iter().map(|e| e.constraint).max().unwrap()
    );
    println!(
        "max c.constraint {}",
        r1cs.c.iter().map(|e| e.constraint).max().unwrap()
    );

    for witness in &r1cs.witnesses {
        println!("Verifying witness...");
        println!("witness.len: {}", witness.len());
        assert_eq!(witness[0], Fr::ONE);
        let mut witness = witness.to_vec();
        while witness.len() < r1cs.num_variables {
            witness.push(Fr::ZERO);
        }
        assert_eq!(witness.len(), r1cs.num_variables);

        let mut aw = vec![Fr::ZERO; r1cs.num_constraints];
        let mut bw = vec![Fr::ZERO; r1cs.num_constraints];
        let mut cw = vec![Fr::ZERO; r1cs.num_constraints];
        for entry in &r1cs.a {
            aw[entry.constraint] += entry.value * witness[entry.signal];
        }
        for entry in &r1cs.b {
            bw[entry.constraint] += entry.value * witness[entry.signal];
        }
        for entry in &r1cs.c {
            cw[entry.constraint] += entry.value * witness[entry.signal];
        }
        let mut failed = 0;
        for i in 0..r1cs.num_constraints {
            if aw[i] * bw[i] != cw[i] {
                if failed < 5 {
                    println!("Constraint {i} failed!");
                }
                failed += 1;
            }
        }
        println!(
            "{:.2}% of costraints failed",
            100.0 * (failed as f64) / (r1cs.num_constraints as f64)
        );
    }
}
