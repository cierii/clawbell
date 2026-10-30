//! Canonical, domain-separated SHA-256 catalog signatures. All server-controlled
//! tool metadata is pinned, including descriptions, schemas and annotations.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
/// Catalog validation failed; never exposes server metadata.
#[derive(Debug, thiserror::Error)]
#[error("invalid_tool_catalog")]
pub struct CatalogError;
/// Build an order-independent catalog digest. JSON object keys are sorted by
/// `serde_json`'s default map representation; array order remains significant.
/// # Errors
/// Rejects duplicate/missing names, invalid schemas and oversized catalogs.
pub fn catalog_digest(tools: &[Value]) -> Result<[u8; 32], CatalogError> {
    if tools.len() > 256 {
        return Err(CatalogError);
    }
    let mut sorted = BTreeMap::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or(CatalogError)?;
        if name.is_empty()
            || name.len() > 256
            || !tool.get("inputSchema").is_some_and(Value::is_object)
            || sorted.insert(name, tool).is_some()
        {
            return Err(CatalogError);
        }
    }
    let encoded = serde_json::to_vec(&sorted).map_err(|_| CatalogError)?;
    if encoded.len() > 1024 * 1024 {
        return Err(CatalogError);
    }
    Ok(Sha256::digest([b"clawbell/catalog/v1\0".as_slice(), &encoded].concat()).into())
}

/// SHA-256 signature of each complete tool definition, including its name,
/// schemas and description. Digests are sorted so list order is insignificant.
/// # Errors
/// Uses the same catalog limits and duplicate-name validation as `catalog_digest`.
pub fn tool_digests(tools: &[Value]) -> Result<Vec<[u8; 32]>, CatalogError> {
    catalog_digest(tools)?;
    let mut digests = tools
        .iter()
        .map(|tool| {
            let encoded = serde_json::to_vec(tool).map_err(|_| CatalogError)?;
            Ok(Sha256::digest([b"clawbell/tool/v1\0".as_slice(), &encoded].concat()).into())
        })
        .collect::<Result<Vec<[u8; 32]>, CatalogError>>()?;
    digests.sort_unstable();
    Ok(digests)
}

/// Canonical SHA-256 argument binding for a one-use owner decision.
/// # Errors
/// Refuses arguments above the protocol inspection bound.
pub fn argument_digest(arguments: &Value) -> Result<String, CatalogError> {
    use std::fmt::Write as _;
    let encoded = serde_json::to_vec(arguments).map_err(|_| CatalogError)?;
    if encoded.len() > 1024 * 1024 {
        return Err(CatalogError);
    }
    let digest = Sha256::digest([b"clawbell/approval/v1\0".as_slice(), &encoded].concat());
    let mut result = String::with_capacity(64);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    Ok(result)
}
