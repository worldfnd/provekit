//! Utility functions for ProveKit FFI bindings.

use {
    crate::types::PKError,
    anyhow::Result,
    std::{ffi::CStr, os::raw::c_char},
};

/// Internal helper to convert C string to owned Rust String.
///
/// This function copies the C string to avoid lifetime issues where the caller
/// might deallocate the C string while Rust code still holds a reference.
///
/// # Safety
///
/// The caller must ensure that `ptr` is a valid null-terminated C string
/// that remains valid for the duration of this function call.
pub unsafe fn c_str_to_str(ptr: *const c_char) -> Result<String, PKError> {
    if ptr.is_null() {
        return Err(PKError::InvalidInput);
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| PKError::Utf8Error)
}

/// Convert a JSON string to TOML format.
///
/// This is needed because the prover expects inputs in TOML format,
/// but the FFI API accepts JSON for easier cross-language compatibility.
pub fn json_to_toml(json_str: &str) -> Result<String, String> {
    // Parse JSON into a generic serde_json::Value
    let value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    // Convert to TOML Value
    let toml_value = json_value_to_toml(&value)
        .ok_or_else(|| "Failed to convert JSON to TOML".to_string())?;

    // Serialize to TOML string
    toml::to_string(&toml_value)
        .map_err(|e| format!("Failed to serialize TOML: {}", e))
}

/// Recursively convert serde_json::Value to toml::Value.
fn json_value_to_toml(json: &serde_json::Value) -> Option<toml::Value> {
    match json {
        serde_json::Value::Null => Some(toml::Value::String(String::new())),
        serde_json::Value::Bool(b) => Some(toml::Value::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(toml::Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Some(toml::Value::Float(f))
            } else {
                None
            }
        }
        serde_json::Value::String(s) => Some(toml::Value::String(s.clone())),
        serde_json::Value::Array(arr) => {
            let toml_arr: Option<Vec<toml::Value>> = arr.iter().map(json_value_to_toml).collect();
            toml_arr.map(toml::Value::Array)
        }
        serde_json::Value::Object(obj) => {
            let mut map = toml::map::Map::new();
            for (k, v) in obj {
                map.insert(k.clone(), json_value_to_toml(v)?);
            }
            Some(toml::Value::Table(map))
        }
    }
}
