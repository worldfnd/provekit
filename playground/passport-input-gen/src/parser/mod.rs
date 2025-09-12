use {
    crate::parser::{
        binary::Binary,
        sod::SOD,
        utils::{fit, load_csca_public_keys},
    },
    base64::{engine::general_purpose::STANDARD, Engine as _},
    noir_bignum_paramgen::compute_barrett_reduction_parameter,
    rsa::{
        pkcs1::DecodeRsaPublicKey,
        pkcs1v15::{Pkcs1v15Sign, Signature},
        pkcs8::DecodePublicKey,
        traits::PublicKeyParts,
        BigUint, RsaPublicKey,
    },
    sha2::{Digest, Sha256},
    std::{fs::File, io::Write, path::Path},
};

mod binary;
mod dsc;
mod oid_registry;
mod sod;
mod types;
mod utils;

pub struct PassportReader {
    pub dg1: Binary,
    pub sod: SOD,
}

const MAX_SIGNED_ATTRIBUTES_SIZE: usize = 200;
const MAX_DG1_SIZE: usize = 95;
const SIG_BYTES: usize = 256;
const MAX_ECONTENT_SIZE: usize = 200;
const MAX_TBS_SIZE: usize = 1500;

// Circuits inputs for
// provekit/noir-examples/noir-passport-examples/complete_age_check
pub struct CircuitInputs {
    dg1:               [u8; MAX_DG1_SIZE],
    dg1_padded_length: usize,

    /// in the format YYYYMMDD
    current_date: u64,

    min_age_required:           u8,
    max_age_required:           u8,
    passport_validity_contents: PassportValidityContent,
}

pub struct PassportValidityContent {
    /// Signed attributes from SOD
    signed_attributes:      [u8; MAX_SIGNED_ATTRIBUTES_SIZE],
    signed_attributes_size: usize,

    /// Encapsulated content info
    econtent:     [u8; MAX_ECONTENT_SIZE],
    econtent_len: usize,

    /// DSC (Document Signer Certificate) public key and signature
    dsc_pubkey:       [u8; SIG_BYTES],
    dsc_barrett_mu:   [u8; SIG_BYTES + 1],
    dsc_signature:    [u8; SIG_BYTES],
    dsc_rsa_exponent: u32,

    /// CSCA (Country Signing Certificate Authority) public key and signature
    // Todo: csca can be different size based on country, but for now we assume 4096 bits for US
    // passport data
    csc_pubkey: [u8; SIG_BYTES * 2],
    csc_barrett_mu:     [u8; (SIG_BYTES * 2) + 1],
    dsc_cert_signature: [u8; SIG_BYTES * 2],
    csc_rsa_exponent:   u32,

    /// Offsets
    dg1_hash_offset:               usize,
    econtent_hash_offset:          usize,
    dsc_pubkey_offset_in_dsc_cert: usize,

    // TBS bytes of the DSC certificate
    dsc_cert:     [u8; MAX_TBS_SIZE],
    dsc_cert_len: usize,
}

impl PassportReader {
    pub fn validate(&self) -> (bool, Option<usize>) {
        // Check1: DG1 Hash check in Econtent
        let dg1_hash = Sha256::digest(&self.dg1.to_number_array());

        let dg1_hash_from_econtent = self
            .sod
            .encap_content_info
            .e_content
            .data_group_hash_values
            .values
            .get(&1)
            .expect("DG1 hash missing")
            .to_number_array();

        assert_eq!(dg1_hash_from_econtent, dg1_hash.to_vec());

        // Check2: Hash(Econtent) check in SignedAttributes
        let econtent_hash = Sha256::digest(
            &self
                .sod
                .encap_content_info
                .e_content
                .bytes
                .to_number_array(),
        );

        let mut msg_digest_from_signed_attr = self
            .sod
            .signer_info
            .signed_attrs
            .message_digest
            .to_number_array();

        if msg_digest_from_signed_attr.len() > 2 && msg_digest_from_signed_attr[0] == 0x04 {
            msg_digest_from_signed_attr = msg_digest_from_signed_attr[2..].to_vec();
        }

        assert_eq!(econtent_hash.as_slice(), msg_digest_from_signed_attr);

        // Check 3: Signature verification of SOD using DSC public key
        let signed_attr_hash =
            Sha256::digest(&self.sod.signer_info.signed_attrs.bytes.to_number_array());

        let public_key_der = self
            .sod
            .certificate
            .tbs
            .subject_public_key_info
            .subject_public_key
            .to_number_array();

        let public_key =
            RsaPublicKey::from_pkcs1_der(&public_key_der).expect("Failed to parse public key");

        let dsc_signature_bytes = self.sod.signer_info.signature.to_number_array();
        let dsc_sig_verify = public_key.verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &signed_attr_hash,
            &dsc_signature_bytes,
        );

        if dsc_sig_verify.is_err() {
            return (false, None);
        }

        assert_eq!(dsc_sig_verify.is_ok(), true);

        // check 4: Signature verification of DSC using CSCA public key
        let all_csca_keys = load_csca_public_keys().expect("Failed to load CSCA public keys");
        let usa_csca_keys = all_csca_keys.get("USA").unwrap();

        assert_eq!(usa_csca_keys.len() > 0, true);

        let tbs_bytes = &self.sod.certificate.tbs.bytes.to_number_array();
        let tbs_digest = Sha256::digest(&tbs_bytes);

        let csca_signature = &self.sod.certificate.signature.to_number_array();

        let mut is_csca_verified = false;
        let mut current_csca_index = 0;

        for csca in usa_csca_keys {
            let der_key = STANDARD.decode(csca.public_key.as_bytes()).unwrap();
            let csca_public_key = RsaPublicKey::from_public_key_der(&der_key).unwrap();

            if let Ok(_) =
                csca_public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &tbs_digest, &csca_signature)
            {
                is_csca_verified = true;
                break;
            }
            current_csca_index += 1;
        }
        return (is_csca_verified, Some(current_csca_index));
    }

    pub fn to_circuit_inputs(
        &self,
        current_date: u64,
        min_age_required: u8,
        max_age_required: u8,
        csca_key_index: usize,
    ) -> CircuitInputs {
        let dg1_padded = fit::<MAX_DG1_SIZE>(&self.dg1.to_number_array());
        let dg1_padded_length = self.dg1.len();

        let signed_attributes = self.sod.signer_info.signed_attrs.bytes.to_number_array();
        let signed_attributes_padded = fit::<MAX_SIGNED_ATTRIBUTES_SIZE>(&signed_attributes);
        let signed_attributes_size = signed_attributes.len();

        let econtent_bytes = self
            .sod
            .encap_content_info
            .e_content
            .bytes
            .to_number_array();

        let econtent_len = econtent_bytes.len();
        let econtent_padded = fit::<MAX_ECONTENT_SIZE>(&econtent_bytes);

        let public_key_der = self
            .sod
            .certificate
            .tbs
            .subject_public_key_info
            .subject_public_key
            .to_number_array();

        let public_key = RsaPublicKey::from_pkcs1_der(&public_key_der).unwrap();

        let public_key_n_vec = public_key.n().to_bytes_be();
        let public_key_n: [u8; SIG_BYTES] = public_key_n_vec
            .try_into()
            .expect("Public key modulus is not 256 bytes");

        let dsc_signature: [u8; SIG_BYTES] = self
            .sod
            .signer_info
            .signature
            .to_number_array()
            .try_into()
            .expect("DSC signature is not 256 bytes");

        let public_key_e = public_key.e();
        let public_key_e_bytes = public_key_e.to_bytes_be();

        let dsc_rsa_exponent = if public_key_e_bytes.len() <= 4 {
            let mut buf = [0u8; 4];
            buf[4 - public_key_e_bytes.len()..].copy_from_slice(&public_key_e_bytes);
            u32::from_be_bytes(buf)
        } else {
            panic!("RSA exponent is larger than 4 bytes");
        };

        let dsc_barrett =
            compute_barrett_reduction_parameter(&BigUint::from_bytes_be(&public_key_n))
                .to_bytes_be();

        let dsc_barrett_mu: [u8; SIG_BYTES + 1] = dsc_barrett
            .try_into()
            .expect(&format!("Barrett mu not {} bytes", SIG_BYTES + 1));

        let all_csca_keys = load_csca_public_keys().expect(
            "Failed to load
        CSCA public keys",
        );
        let usa_csca_keys = all_csca_keys.get("USA").unwrap();

        let csca_public_key_pem = &usa_csca_keys[csca_key_index].public_key;
        let der_key = STANDARD.decode(csca_public_key_pem.as_bytes()).unwrap();
        let csca_public_key =
            RsaPublicKey::from_public_key_der(&der_key).expect("Failed to parse CSCA public key");

        let csca_public = csca_public_key.n().to_bytes_be();
        let csca_public_n: [u8; SIG_BYTES * 2] = csca_public
            .try_into()
            .expect(&format!("CSCA key not {} bytes", SIG_BYTES * 2));

        let csca_rsa_exponent_bytes = csca_public_key.e().to_bytes_be();
        let csca_rsa_exponent = if csca_rsa_exponent_bytes.len() <= 4 {
            let mut buf = [0u8; 4];
            buf[4 - csca_rsa_exponent_bytes.len()..].copy_from_slice(&csca_rsa_exponent_bytes);
            u32::from_be_bytes(buf)
        } else {
            panic!("RSA exponent is larger than 4 bytes");
        };

        let csca_barrett =
            compute_barrett_reduction_parameter(&BigUint::from_bytes_be(&csca_public_n))
                .to_bytes_be();

        let csca_barrett_mu: [u8; SIG_BYTES * 2 + 1] = csca_barrett
            .try_into()
            .expect(&format!("CSCA mu not {} bytes", SIG_BYTES * 2 + 1));

        let csca_signature = self.sod.certificate.signature.to_number_array();
        let csca_signature: [u8; SIG_BYTES * 2] = csca_signature
            .clone()
            .try_into()
            .expect(&format!("CSCA sig not {} bytes", SIG_BYTES * 2));

        // offsets
        let dg1_hash = Sha256::digest(&self.dg1.to_number_array());
        let econtent_hash = Sha256::digest(&econtent_bytes);

        let dg1_hash_offset = econtent_bytes
            .windows(dg1_hash.len())
            .position(|window| window == dg1_hash.as_slice())
            .expect("DG1 hash not found in eContent");

        let econtent_hash_offset = signed_attributes
            .windows(econtent_hash.len())
            .position(|window| window == econtent_hash.as_slice())
            .expect("EContent hash not found in signed attributes");

        let tbs_bytes = self.sod.certificate.tbs.bytes.to_number_array();
        let tbs_bytes_len = tbs_bytes.len();
        let dsc_cert = fit::<MAX_TBS_SIZE>(&tbs_bytes);

        let dsc_pubkey_offset_in_dsc_cert = tbs_bytes
            .windows(public_key_n.len())
            .position(|window| window == public_key_n.as_slice())
            .expect("Public key not found in DSC cert");

        CircuitInputs {
            dg1: dg1_padded,
            dg1_padded_length,
            current_date,
            min_age_required,
            max_age_required,
            passport_validity_contents: PassportValidityContent {
                signed_attributes: signed_attributes_padded,
                signed_attributes_size,
                econtent: econtent_padded,
                econtent_len,
                dsc_pubkey: public_key_n,
                dsc_barrett_mu,
                dsc_signature,
                dsc_rsa_exponent,
                csc_pubkey: csca_public_n,
                csc_barrett_mu: csca_barrett_mu,
                dsc_cert_signature: csca_signature,
                csc_rsa_exponent: csca_rsa_exponent,
                dg1_hash_offset,
                econtent_hash_offset,
                dsc_pubkey_offset_in_dsc_cert,
                dsc_cert,
                dsc_cert_len: tbs_bytes_len,
            },
        }
    }
}

impl CircuitInputs {
    pub fn to_toml_string(&self) -> String {
        let mut toml_content = String::new();

        toml_content.push_str(&format!("dg1 = {:?}\n", self.dg1));
        toml_content.push_str(&format!("dg1_padded_length = {}\n", self.dg1_padded_length));
        toml_content.push_str(&format!("current_date = {}\n", self.current_date));
        toml_content.push_str(&format!("min_age_required = {}\n", self.min_age_required));
        toml_content.push_str(&format!("max_age_required = {}\n", self.max_age_required));

        toml_content.push_str("\n[passport_validity_contents]\n");
        toml_content.push_str(&format!(
            "signed_attributes = {:?}\n",
            self.passport_validity_contents.signed_attributes
        ));
        toml_content.push_str(&format!(
            "signed_attributes_size = {}\n",
            self.passport_validity_contents.signed_attributes_size
        ));

        toml_content.push_str(&format!(
            "econtent = {:?}\n",
            self.passport_validity_contents.econtent
        ));
        toml_content.push_str(&format!(
            "econtent_len = {}\n",
            self.passport_validity_contents.econtent_len
        ));

        toml_content.push_str(&format!(
            "dsc_signature = {:?}\n",
            self.passport_validity_contents.dsc_signature
        ));
        toml_content.push_str(&format!(
            "dsc_rsa_exponent = {}\n",
            self.passport_validity_contents.dsc_rsa_exponent
        ));
        toml_content.push_str(&format!(
            "dsc_pubkey = {:?}\n",
            self.passport_validity_contents.dsc_pubkey
        ));
        toml_content.push_str(&format!(
            "dsc_barrett_mu = {:?}\n",
            self.passport_validity_contents.dsc_barrett_mu
        ));

        toml_content.push_str(&format!(
            "csc_pubkey = {:?}\n",
            self.passport_validity_contents.csc_pubkey
        ));
        toml_content.push_str(&format!(
            "csc_barrett_mu = {:?}\n",
            self.passport_validity_contents.csc_barrett_mu
        ));
        toml_content.push_str(&format!(
            "dsc_cert_signature = {:?}\n",
            self.passport_validity_contents.dsc_cert_signature
        ));
        toml_content.push_str(&format!(
            "csc_rsa_exponent = {}\n",
            self.passport_validity_contents.csc_rsa_exponent
        ));

        toml_content.push_str(&format!(
            "dg1_hash_offset = {}\n",
            self.passport_validity_contents.dg1_hash_offset
        ));
        toml_content.push_str(&format!(
            "econtent_hash_offset = {}\n",
            self.passport_validity_contents.econtent_hash_offset
        ));
        toml_content.push_str(&format!(
            "dsc_pubkey_offset_in_dsc_cert = {}\n",
            self.passport_validity_contents
                .dsc_pubkey_offset_in_dsc_cert
        ));
        toml_content.push_str(&format!(
            "dsc_cert = {:?}\n",
            self.passport_validity_contents.dsc_cert
        ));
        toml_content.push_str(&format!(
            "dsc_cert_len = {}\n",
            self.passport_validity_contents.dsc_cert_len
        ));

        toml_content
    }

    pub fn save_to_toml_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let toml_content = self.to_toml_string();
        let mut file = File::create(path)?;
        file.write_all(toml_content.as_bytes())?;
        Ok(())
    }
}
