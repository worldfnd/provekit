use {crate::parser::utils::OidEntry, lazy_static::lazy_static, std::collections::HashMap};

lazy_static! {
    pub static ref REGISTRY: HashMap<&'static str, OidEntry> = load_oids();
}
/// Returns a lookup table for the Object Identifiers that are relevant to the
/// passport input generator.
///
/// The previous version of this registry tried to mirror a “complete” OID
/// catalogue. That was hard to maintain and pulled in thousands of identifiers
/// that are never touched by the parser. The routines that consume this
/// registry only require a small set of entries to render human readable names
/// for:
///
/// * CMS signed attributes that appear in SOD files (content type, message
///   digest, signing time).
/// * The hash algorithms that are supported by the parser (SHA-* family).
/// * Common X.509 RDN attributes so that certificate issuers/subjects remain
///   readable.
/// * Frequently used X.509 extensions such as key usage and authority key
///   identifiers.
/// * ICAO MRTD specific identifiers (e.g. `mRTDSignatureData`).
///
/// Keeping the list focused makes it clear which identifiers we rely on and
/// avoids carrying around a huge hard-coded list that is difficult to audit.
fn load_oids() -> HashMap<&'static str, OidEntry> {
    HashMap::from([
        // PKCS#9 signed attributes used in CMS / SOD structures
        ("1.2.840.113549.1.9.3", OidEntry {
            d: "contentType",
            c: "PKCS #9",
            w: false,
        }),
        ("1.2.840.113549.1.9.4", OidEntry {
            d: "messageDigest",
            c: "PKCS #9",
            w: false,
        }),
        ("1.2.840.113549.1.9.5", OidEntry {
            d: "signingTime",
            c: "PKCS #9",
            w: false,
        }),
        // CMS eContent type for ICAO LDS security objects
        ("2.23.136.1.1.1", OidEntry {
            d: "mRTDSignatureData",
            c: "ICAO MRTD",
            w: false,
        }),
        // Hash algorithms recognised by the parser
        ("1.3.14.3.2.26", OidEntry {
            d: "sha-1",
            c: "NIST Algorithm",
            w: false,
        }),
        ("2.16.840.1.101.3.4.2.1", OidEntry {
            d: "sha-256",
            c: "NIST Algorithm",
            w: false,
        }),
        ("2.16.840.1.101.3.4.2.2", OidEntry {
            d: "sha-384",
            c: "NIST Algorithm",
            w: false,
        }),
        ("2.16.840.1.101.3.4.2.3", OidEntry {
            d: "sha-512",
            c: "NIST Algorithm",
            w: false,
        }),
        ("2.16.840.1.101.3.4.2.4", OidEntry {
            d: "sha-224",
            c: "NIST Algorithm",
            w: false,
        }),
        // Common X.509 RDN attributes so issuer/subject strings stay readable
        ("2.5.4.3", OidEntry {
            d: "commonName",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.4", OidEntry {
            d: "surname",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.5", OidEntry {
            d: "serialNumber",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.6", OidEntry {
            d: "countryName",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.7", OidEntry {
            d: "localityName",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.8", OidEntry {
            d: "stateOrProvinceName",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.9", OidEntry {
            d: "streetAddress",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.10", OidEntry {
            d: "organizationName",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.11", OidEntry {
            d: "organizationalUnitName",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.12", OidEntry {
            d: "title",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.13", OidEntry {
            d: "description",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.17", OidEntry {
            d: "postalCode",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.42", OidEntry {
            d: "givenName",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.43", OidEntry {
            d: "initials",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.46", OidEntry {
            d: "dnQualifier",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        ("2.5.4.65", OidEntry {
            d: "pseudonym",
            c: "X.520 Distinguished Name",
            w: false,
        }),
        // Commonly encountered X.509 extensions
        ("2.5.29.14", OidEntry {
            d: "subjectKeyIdentifier",
            c: "X.509 extension",
            w: false,
        }),
        ("2.5.29.15", OidEntry {
            d: "keyUsage",
            c: "X.509 extension",
            w: false,
        }),
        ("2.5.29.17", OidEntry {
            d: "subjectAltName",
            c: "X.509 extension",
            w: false,
        }),
        ("2.5.29.19", OidEntry {
            d: "basicConstraints",
            c: "X.509 extension",
            w: false,
        }),
        ("2.5.29.31", OidEntry {
            d: "cRLDistributionPoints",
            c: "X.509 extension",
            w: false,
        }),
        ("2.5.29.32", OidEntry {
            d: "certificatePolicies",
            c: "X.509 extension",
            w: false,
        }),
        ("2.5.29.32.0", OidEntry {
            d: "anyPolicy",
            c: "X.509 extension",
            w: false,
        }),
        ("2.5.29.35", OidEntry {
            d: "authorityKeyIdentifier",
            c: "X.509 extension",
            w: false,
        }),
        ("2.5.29.37", OidEntry {
            d: "extKeyUsage",
            c: "X.509 extension",
            w: false,
        }),
    ])
}
