use {
    crate::types::WhirWitness,
    provekit_backend_bn254::FieldElement,
    provekit_common::utils::serde_ark_vec,
    serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer},
    whir::protocols::{
        irs_commit::{Evaluations, Witness},
        matrix_commit,
    },
};

pub fn serialize<S: Serializer>(w: &WhirWitness, s: S) -> Result<S::Ok, S::Error> {
    let mut st = s.serialize_struct("WhirWitness", 4)?;
    st.serialize_field("masks", &ArkVecRef(&w.masks))?;
    st.serialize_field("matrix", &ArkVecRef(&w.matrix))?;
    st.serialize_field("matrix_witness", &w.matrix_witness)?;
    st.serialize_field("out_of_domain", &EvaluationsRef(&w.out_of_domain))?;
    st.end()
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<WhirWitness, D::Error> {
    let m = WitnessMirror::deserialize(d)?;
    Ok(Witness {
        masks:          m.masks,
        matrix:         m.matrix,
        matrix_witness: m.matrix_witness,
        out_of_domain:  Evaluations {
            points: m.out_of_domain.points,
            matrix: m.out_of_domain.matrix,
        },
    })
}

struct ArkVecRef<'a>(&'a Vec<FieldElement>);

impl Serialize for ArkVecRef<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde_ark_vec::serialize(self.0, s)
    }
}

struct EvaluationsRef<'a>(&'a Evaluations<FieldElement>);

impl Serialize for EvaluationsRef<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Evaluations", 2)?;
        st.serialize_field("points", &ArkVecRef(&self.0.points))?;
        st.serialize_field("matrix", &ArkVecRef(&self.0.matrix))?;
        st.end()
    }
}

#[derive(Deserialize)]
struct WitnessMirror {
    #[serde(with = "serde_ark_vec")]
    masks:          Vec<FieldElement>,
    #[serde(with = "serde_ark_vec")]
    matrix:         Vec<FieldElement>,
    matrix_witness: matrix_commit::Witness,
    out_of_domain:  EvaluationsMirror,
}

#[derive(Deserialize)]
struct EvaluationsMirror {
    #[serde(with = "serde_ark_vec")]
    points: Vec<FieldElement>,
    #[serde(with = "serde_ark_vec")]
    matrix: Vec<FieldElement>,
}
