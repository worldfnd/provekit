#[cfg(target_arch = "wasm32")]
pub use self::wasm_stubs::{ConstraintsLayout, WitnessLayout};
#[cfg(not(target_arch = "wasm32"))]
pub use mavros_vm::{ConstraintsLayout, WitnessLayout};
use {
    crate::{Bn254Field, FieldElement},
    anyhow::{ensure, Result},
    ark_ff::Zero as _,
    noirc_abi::Abi,
    provekit_common::{HashConfig, WhirR1CSScheme, R1CS},
    serde::{Deserialize, Serialize},
};
#[cfg(not(target_arch = "wasm32"))]
use {
    anyhow::Context as _,
    mavros_artifacts::{ParamVisibility, WitnessManifest},
    noirc_abi::AbiVisibility,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavrosProver {
    #[serde(with = "provekit_common::utils::serde_jsonify")]
    pub abi:                Abi,
    pub num_public_inputs:  usize,
    pub whir_for_witness:   WhirR1CSScheme<Bn254Field>,
    pub binary:             Vec<u64>,
    pub constraints_layout: ConstraintsLayout,
    pub witness_layout:     WitnessLayout,
    pub hash_config:        HashConfig,
    pub column_map:         MavrosColumnMap,
    pub mavros_digest:      [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavrosSchemeData {
    #[serde(with = "provekit_common::utils::serde_jsonify")]
    pub abi:                Abi,
    pub num_public_inputs:  usize,
    pub r1cs:               R1CS<FieldElement>,
    pub whir_for_witness:   WhirR1CSScheme<Bn254Field>,
    pub binary:             Vec<u64>,
    pub constraints_layout: ConstraintsLayout,
    pub witness_layout:     WitnessLayout,
    pub hash_config:        HashConfig,
    pub column_map:         MavrosColumnMap,
    pub mavros_digest:      [u8; 32],
}

/// Permutes Mavros witness columns so the public parameters, then the public
/// return, occupy columns `1..=n`; other columns keep their relative order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CompactColumnMap", into = "CompactColumnMap")]
pub struct MavrosColumnMap {
    map:            Vec<u32>,
    public_columns: Vec<usize>,
}

#[derive(Serialize, Deserialize)]
struct CompactColumnMap {
    len:            usize,
    public_columns: Vec<usize>,
}

impl TryFrom<CompactColumnMap> for MavrosColumnMap {
    type Error = anyhow::Error;

    fn try_from(compact: CompactColumnMap) -> Result<Self> {
        Self::build(compact.len, compact.public_columns)
    }
}

impl From<MavrosColumnMap> for CompactColumnMap {
    fn from(map: MavrosColumnMap) -> Self {
        Self {
            len:            map.map.len(),
            public_columns: map.public_columns,
        }
    }
}

impl MavrosColumnMap {
    fn build(len: usize, public_columns: Vec<usize>) -> Result<Self> {
        ensure!(len > 0, "a Mavros witness has at least the constant column");
        let mut map = vec![u32::MAX; len];
        map[0] = 0;
        for (new, &old) in public_columns.iter().enumerate() {
            ensure!(
                old > 0 && old < len,
                "public column {old} lies outside the {len} witness columns"
            );
            ensure!(
                map[old] == u32::MAX,
                "public column {old} is listed more than once"
            );
            map[old] = (new + 1) as u32;
        }
        let mut next = public_columns.len() + 1;
        for slot in map.iter_mut().skip(1) {
            if *slot == u32::MAX {
                *slot = next as u32;
                next += 1;
            }
        }
        Ok(Self {
            map,
            public_columns,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl MavrosColumnMap {
    pub fn from_manifest(
        manifest: &WitnessManifest,
        abi: &Abi,
        witness_count: usize,
    ) -> Result<Self> {
        ensure!(
            manifest.parameters.len() == abi.parameters.len(),
            "Mavros manifest lists {} parameters but the ABI declares {}",
            manifest.parameters.len(),
            abi.parameters.len()
        );
        ensure!(
            abi.return_type.is_some() == manifest.returns.is_some(),
            "Mavros manifest and the ABI disagree on whether `main` returns a value"
        );

        let mut public_columns = Vec::new();
        for (param, entry) in abi.parameters.iter().zip(&manifest.parameters) {
            ensure!(
                param.name == entry.name,
                "Mavros manifest parameter `{}` does not match ABI parameter `{}`",
                entry.name,
                param.name
            );
            ensure!(
                param.typ.field_count() as usize == entry.width,
                "Mavros manifest gives parameter `{}` {} columns but the ABI flattens it to {}",
                entry.name,
                entry.width,
                param.typ.field_count()
            );
            ensure!(
                visibility_of(param.visibility) == entry.visibility,
                "Mavros manifest and the ABI disagree on the visibility of `{}`",
                entry.name
            );
            // A private parameter may have no columns: Mavros elides an unused one.
            if entry.visibility == ParamVisibility::Public && entry.width > 0 {
                let start = entry.column_start.with_context(|| {
                    format!("public parameter `{}` has no witness columns", entry.name)
                })?;
                public_columns.extend(start..start + entry.width);
            }
        }
        if let (Some(ret), Some(abi_return)) = (manifest.returns, abi.return_type.as_ref()) {
            ensure!(
                abi_return.abi_type.field_count() as usize == ret.len,
                "Mavros manifest gives the return {} columns but the ABI flattens it to {}",
                ret.len,
                abi_return.abi_type.field_count()
            );
            ensure!(
                visibility_of(abi_return.visibility) == ret.visibility,
                "Mavros manifest and the ABI disagree on the visibility of the return"
            );
            if ret.visibility == ParamVisibility::Public && ret.len > 0 {
                let start = ret
                    .column_start
                    .context("the public return has no witness columns")?;
                public_columns.extend(start..start + ret.len);
            }
        }
        Self::build(witness_count, public_columns)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn visibility_of(visibility: AbiVisibility) -> ParamVisibility {
    match visibility {
        AbiVisibility::Public => ParamVisibility::Public,
        AbiVisibility::Private => ParamVisibility::Private,
        AbiVisibility::DataBus => ParamVisibility::DataBus,
    }
}

impl MavrosColumnMap {
    pub fn num_public_inputs(&self) -> usize {
        self.public_columns.len()
    }

    pub fn constraint_column(&self, column: usize) -> usize {
        self.map[column] as usize
    }

    pub fn permute(&self, values: Vec<FieldElement>) -> Vec<FieldElement> {
        if self.is_identity() {
            return values;
        }
        let mut out = vec![FieldElement::zero(); values.len()];
        for (old, value) in values.into_iter().enumerate() {
            out[self.constraint_column(old)] = value;
        }
        out
    }

    fn is_identity(&self) -> bool {
        self.public_columns
            .iter()
            .enumerate()
            .all(|(new, &old)| old == new + 1)
    }
}

// Wire-compatible stubs for WASM targets where mavros_vm (C bindings) is
// unavailable. Field names, types, and ordering MUST match the real mavros_vm
// types exactly.
#[cfg(target_arch = "wasm32")]
mod wasm_stubs {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct WitnessLayout {
        pub algebraic_size:      usize,
        pub multiplicities_size: usize,
        pub challenges_size:     usize,
        pub logup_repetitions:   usize,
        pub tables_data_size:    usize,
        pub lookups_data_size:   usize,
    }

    impl WitnessLayout {
        /// Return the total number of Mavros witness values.
        pub const fn size(&self) -> usize {
            self.algebraic_size
                + self.multiplicities_size
                + self.challenges_size
                + self.tables_data_size
                + self.lookups_data_size
        }

        /// Return the number of witness values committed before challenges.
        pub const fn pre_commitment_size(&self) -> usize {
            self.algebraic_size + self.multiplicities_size
        }

        /// Return the number of witness values computed after challenges.
        pub const fn post_commitment_size(&self) -> usize {
            self.challenges_size + self.tables_data_size + self.lookups_data_size
        }
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct ConstraintsLayout {
        pub algebraic_size:    usize,
        pub tables_data_size:  usize,
        pub lookups_data_size: usize,
    }

    impl ConstraintsLayout {
        /// Return the total number of Mavros constraint values.
        pub const fn size(&self) -> usize {
            self.algebraic_size + self.tables_data_size + self.lookups_data_size
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use {
        super::*,
        mavros_artifacts::{ManifestParam, ReturnSlot},
        noirc_abi::{AbiParameter, AbiReturnType, AbiType},
    };

    fn field_param(name: &str, visibility: AbiVisibility) -> AbiParameter {
        AbiParameter {
            name: name.to_string(),
            typ: AbiType::Field,
            visibility,
        }
    }

    fn param(
        name: &str,
        visibility: ParamVisibility,
        column_start: Option<usize>,
    ) -> ManifestParam {
        ManifestParam {
            name: name.to_string(),
            visibility,
            width: 1,
            column_start,
        }
    }

    const WITNESS_COUNT: usize = 12;

    /// `fn main(x: Field, y: pub Field) -> pub Field` with Mavros columns
    /// `[1, y, x, t3, t4, ret, t6 | m7, m8 | c9, d10, l11]`: the public `y`
    /// first, the private `x` next, the computed return after main's work.
    fn abi_with_return() -> Abi {
        Abi {
            parameters:  vec![
                field_param("x", AbiVisibility::Private),
                field_param("y", AbiVisibility::Public),
            ],
            return_type: Some(AbiReturnType {
                abi_type:   AbiType::Field,
                visibility: AbiVisibility::Public,
            }),
            error_types: Default::default(),
        }
    }

    fn manifest_with_return() -> WitnessManifest {
        WitnessManifest {
            parameters: vec![
                param("x", ParamVisibility::Private, Some(2)),
                param("y", ParamVisibility::Public, Some(1)),
            ],
            returns:    Some(ReturnSlot {
                column_start: Some(5),
                len:          1,
                visibility:   ParamVisibility::Public,
            }),
        }
    }

    #[test]
    fn column_remap_brings_the_return_forward() {
        let map = MavrosColumnMap::from_manifest(
            &manifest_with_return(),
            &abi_with_return(),
            WITNESS_COUNT,
        )
        .unwrap();
        assert_eq!(map.num_public_inputs(), 2);
        // y stays at 1, ret → 2, then x, t3, t4, t6 keep their relative order.
        let expected: Vec<u32> = vec![0, 1, 3, 4, 5, 2, 6, 7, 8, 9, 10, 11];
        assert_eq!(map.map, expected);
        assert_eq!(map.constraint_column(5), 2);
        assert_eq!(map.constraint_column(2), 3);
        assert_eq!(map.constraint_column(7), 7);

        let w1: Vec<FieldElement> = (0..9).map(|i| FieldElement::from(100 + i as u64)).collect();
        let permuted = map.permute(w1.clone());
        assert_eq!(permuted[1], w1[1]);
        assert_eq!(permuted[2], w1[5]);
        assert_eq!(permuted[3], w1[2]);
        assert_eq!(permuted[5], w1[4]);
        assert_eq!(&permuted[7..], &w1[7..]);

        let derivatives: Vec<FieldElement> =
            (0..12).map(|i| FieldElement::from(1u64 << i)).collect();
        let remapped = map.permute(derivatives.clone());
        assert_eq!(remapped[0], derivatives[0]);
        assert_eq!(remapped[2], derivatives[5]);
        assert_eq!(remapped[3], derivatives[2]);
    }

    #[test]
    fn manifest_matches_abi() {
        let abi = abi_with_return();
        let manifest = manifest_with_return();
        let fails = |manifest: &WitnessManifest, abi: &Abi| {
            MavrosColumnMap::from_manifest(manifest, abi, WITNESS_COUNT).is_err()
        };

        let mut renamed = manifest.clone();
        renamed.parameters[1].name = "z".into();
        assert!(fails(&renamed, &abi));

        let mut hidden = manifest.clone();
        hidden.parameters[1].visibility = ParamVisibility::Private;
        assert!(fails(&hidden, &abi));

        let mut elided_public = manifest.clone();
        elided_public.parameters[1].column_start = None;
        assert!(fails(&elided_public, &abi));

        // An unused private parameter has no columns and changes nothing.
        let mut elided_private = manifest.clone();
        elided_private.parameters[0].column_start = None;
        let map = MavrosColumnMap::from_manifest(&elided_private, &abi, WITNESS_COUNT).unwrap();
        assert_eq!(map.num_public_inputs(), 2);

        let mut duplicated = manifest.clone();
        duplicated.returns.as_mut().unwrap().column_start = Some(1);
        assert!(fails(&duplicated, &abi));

        let mut wide_return = abi.clone();
        wide_return.return_type.as_mut().unwrap().abi_type = AbiType::Tuple {
            fields: vec![AbiType::Field, AbiType::Field],
        };
        assert!(fails(&manifest, &wide_return));

        let mut private_return = abi.clone();
        private_return.return_type.as_mut().unwrap().visibility = AbiVisibility::Private;
        assert!(fails(&manifest, &private_return));
        let mut private_manifest = manifest.clone();
        private_manifest.returns.as_mut().unwrap().visibility = ParamVisibility::Private;
        let map = MavrosColumnMap::from_manifest(&private_manifest, &private_return, WITNESS_COUNT)
            .unwrap();
        assert_eq!(map.num_public_inputs(), 1);
    }
}
