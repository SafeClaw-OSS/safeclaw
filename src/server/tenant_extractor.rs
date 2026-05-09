//! `X-Safeclaw-Tenant` extractor.
//!
//! Pro relay injects this header after sc_xxx → tenant_id translation. The
//! daemon never sees raw API keys.

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap},
};

use crate::error::{AppError, Result};

pub const HEADER: &str = "x-safeclaw-tenant";

#[derive(Debug, Clone)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self> {
        let raw = headers
            .get(HEADER)
            .ok_or_else(|| AppError::BadRequest(format!("missing {} header", HEADER)))?
            .to_str()
            .map_err(|_| AppError::BadRequest(format!("non-ascii {} header", HEADER)))?
            .trim();
        if raw.is_empty() {
            return Err(AppError::BadRequest(format!("empty {} header", HEADER)));
        }
        validate(raw)?;
        Ok(TenantId(raw.to_string()))
    }
}

fn validate(id: &str) -> Result<()> {
    if id.len() > 128 {
        return Err(AppError::BadRequest("tenant_id too long".into()));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest("tenant_id has illegal chars".into()));
    }
    Ok(())
}

impl<S: Send + Sync> FromRequestParts<S> for TenantId {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        Self::from_headers(&parts.headers)
    }
}
