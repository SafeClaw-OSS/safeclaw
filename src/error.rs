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

impl AppError {
    /// `(http status u16, machine code, human message)` — the error's wire
    /// projection. Shared by the axum `IntoResponse` below AND the hudsucker
    /// 23294 API face (`proxy::api_face`), so both ports map an error identically
    /// without depending on each other's `http`/`StatusCode` type.
    pub fn parts(&self) -> (u16, &'static str, String) {
        match self {
            AppError::BadRequest(msg) => (400, "bad_request", msg.clone()),
            AppError::Unauthorized(msg) => (401, "unauthorized", msg.clone()),
            AppError::Forbidden(msg) => (403, "forbidden", msg.clone()),
            AppError::NotFound => (404, "not_found", "Not found".to_string()),
            AppError::Conflict(msg) => (409, "conflict", msg.clone()),
            AppError::VaultLocked => (
                423,
                "vault_locked",
                "vault locked — run `sc up` to unlock, then retry".to_string(),
            ),
            AppError::TooManyRequests => (429, "rate_limited", "Rate limit exceeded".to_string()),
            AppError::Internal(msg) => {
                tracing::error!("internal error: {}", msg);
                (500, "internal", "Internal server error".to_string())
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
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
