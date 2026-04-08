use {
    anyhow::{Context, Result},
    provekit_common::spark::R1CSSparkQuery,
    serde::{de::DeserializeOwned, Deserialize, Serialize},
    std::{
        io::{Read, Write},
        path::PathBuf,
    },
};

#[derive(Serialize, Deserialize)]
pub struct SparkRequest {
    pub circuit:     String,
    pub spark_query: R1CSSparkQuery,
    pub output:      PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct SparkResponse {
    pub ok:    bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn write_message(stream: &mut impl Write, msg: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(msg).context("serializing message")?;
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .context("writing message length")?;
    stream.write_all(&bytes).context("writing message body")?;
    stream.flush().context("flushing stream")?;
    Ok(())
}

pub fn read_message<T: DeserializeOwned>(stream: &mut impl Read) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("reading message length")?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .context("reading message body")?;

    serde_json::from_slice(&buf).context("parsing message JSON")
}
