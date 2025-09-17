use base64::{engine::general_purpose, Engine as _};

#[derive(Debug, Clone)]
pub struct Binary {
    pub data: Vec<u8>,
}

impl Binary {
    pub fn new(data: Vec<u8>) -> Self {
        Binary { data }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Binary {
            data: data.to_vec(),
        }
    }

    pub fn from_base64(b64: &str) -> Result<Self, base64::DecodeError> {
        let data = general_purpose::STANDARD.decode(b64)?;
        Ok(Binary::new(data))
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn slice(&self, start: usize, end: usize) -> Binary {
        Binary::new(self.data[start..end].to_vec())
    }

    pub fn to_string_ascii(&self) -> String {
        String::from_utf8_lossy(&self.data).to_string()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.data))
    }

    pub fn equals(&self, other: &Binary) -> bool {
        self.data.eq(&other.data)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let data = hex::decode(hex_str)?;
        Ok(Binary::new(data))
    }
}

impl PartialEq for Binary {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}
