use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound,
    Conflict(String),
    /// Vault is locked (no in-memory key). Distinct from `Conflict` so the agent
    /// can tell "unlock needed → run `sc up`" apart from other 409s. HTTP 423.
    VaultLocked,
    TooManyRequests,
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, code) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone(), "bad_request"),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone(), "unauthorized"),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone(), "forbidden"),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string(), "not_found"),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone(), "conflict"),
            AppError::VaultLocked => (
                StatusCode::LOCKED,
                "vault locked — run `sc up` to unlock, then retry".to_string(),
                "vault_locked",
            ),
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string(), "rate_limited"),
            AppError::Internal(msg) => {
                tracing::error!("internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), "internal")
            }
        };
        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::NotFound => write!(f, "Not found"),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::VaultLocked => write!(f, "Vault locked"),
            AppError::TooManyRequests => write!(f, "Rate limit exceeded"),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Internal(format!("IO error: {}", e))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Internal(format!("JSON error: {}", e))
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(e: base64::DecodeError) -> Self {
        AppError::BadRequest(format!("Base64 decode error: {}", e))
    }
}
