/// Locked proxy response generators.
///
/// When the vault is locked, the proxy returns API-format-aware placeholder
/// responses. In v2, the format is auto-detected from the upstream URL.
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Render a locked response by template name (legacy, still used as fallback).
pub fn render(template: &str, is_stream: bool, admin_url: &str) -> Option<Response> {
    let message = default_locked_message(admin_url);
    match template {
        "anthropic" => Some(anthropic(is_stream, &message)),
        "openai" => Some(openai(is_stream, &message)),
        "openai-responses" => Some(openai_responses(is_stream, &message)),
        "gemini" => Some(gemini(&message)),
        _ => None,
    }
}

/// Auto-detect API format from upstream URL and render appropriate locked response.
/// If `custom_message` is provided, it replaces the default locked message.
pub fn render_for_upstream(
    upstream_url: &str,
    is_stream: bool,
    admin_url: &str,
    custom_message: Option<&str>,
) -> Option<Response> {
    let message = match custom_message {
        Some(msg) => msg.to_string(),
        None => default_locked_message(admin_url),
    };

    let url_lower = upstream_url.to_lowercase();
    if url_lower.contains("anthropic.com") {
        Some(anthropic(is_stream, &message))
    } else if url_lower.contains("generativelanguage.googleapis.com") {
        Some(gemini(&message))
    } else if url_lower.contains("openai.com") || url_lower.contains("groq.com")
        || url_lower.contains("deepseek.com") || url_lower.contains("openrouter.ai")
    {
        Some(openai(is_stream, &message))
    } else {
        // Generic fallback: use OpenAI format (most common)
        Some(openai(is_stream, &message))
    }
}

fn default_locked_message(admin_url: &str) -> String {
    let display = admin_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    format!(
        "🔒 I can't respond — vault is locked.\n\nUnlock on SafeClaw to continue:\n[{display}]({admin_url})"
    )
}

fn msg_id() -> String {
    format!("msg_locked_{}", now_secs())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Anthropic Messages API locked response
fn anthropic(is_stream: bool, message: &str) -> Response {
    let content = message;
    let id = msg_id();

    if !is_stream {
        let body = serde_json::to_string(&serde_json::json!({
            "id": id, "type": "message", "role": "assistant",
            "content": [{ "type": "text", "text": content }],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn", "stop_sequence": null,
            "usage": { "input_tokens": 0, "output_tokens": 0 },
        }))
        .unwrap_or_default();
        return (
            StatusCode::OK,
            [("content-type", "application/json")],
            body,
        )
            .into_response();
    }

    let sse_lines = vec![
        format!(
            "event: message_start\ndata: {}\n\n",
            serde_json::json!({
                "type": "message_start",
                "message": {
                    "id": &id, "type": "message", "role": "assistant", "content": [],
                    "model": "claude-sonnet-4-20250514",
                    "stop_reason": null, "stop_sequence": null,
                    "usage": { "input_tokens": 0, "output_tokens": 0 },
                }
            })
        ),
        format!(
            "event: content_block_start\ndata: {}\n\n",
            serde_json::json!({
                "type": "content_block_start", "index": 0,
                "content_block": { "type": "text", "text": "" }
            })
        ),
        format!(
            "event: content_block_delta\ndata: {}\n\n",
            serde_json::json!({
                "type": "content_block_delta", "index": 0,
                "delta": { "type": "text_delta", "text": content }
            })
        ),
        format!(
            "event: content_block_stop\ndata: {}\n\n",
            serde_json::json!({ "type": "content_block_stop", "index": 0 })
        ),
        format!(
            "event: message_delta\ndata: {}\n\n",
            serde_json::json!({
                "type": "message_delta",
                "delta": { "stop_reason": "end_turn", "stop_sequence": null },
                "usage": { "output_tokens": 0 }
            })
        ),
        format!(
            "event: message_stop\ndata: {}\n\n",
            serde_json::json!({ "type": "message_stop" })
        ),
    ];

    (
        StatusCode::OK,
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
            ("connection", "keep-alive"),
        ],
        sse_lines.join(""),
    )
        .into_response()
}

/// OpenAI Chat Completions locked response
fn openai(is_stream: bool, message: &str) -> Response {
    let content = message;
    let now = now_secs();

    if !is_stream {
        let body = serde_json::to_string(&serde_json::json!({
            "id": "safeclaw-locked",
            "object": "chat.completion",
            "created": now,
            "model": "safeclaw-locked",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": content },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0 },
        }))
        .unwrap_or_default();
        return (StatusCode::OK, [("content-type", "application/json")], body).into_response();
    }

    let content_chunk = serde_json::json!({
        "id": "chatcmpl-locked", "object": "chat.completion.chunk",
        "created": now, "model": "gpt-4o",
        "choices": [{ "index": 0, "delta": { "role": "assistant", "content": content }, "finish_reason": null }],
    });
    let done_chunk = serde_json::json!({
        "id": "chatcmpl-locked", "object": "chat.completion.chunk",
        "created": now, "model": "gpt-4o",
        "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
    });

    let sse = format!(
        "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        serde_json::to_string(&content_chunk).unwrap_or_default(),
        serde_json::to_string(&done_chunk).unwrap_or_default(),
    );

    (
        StatusCode::OK,
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
            ("connection", "keep-alive"),
        ],
        sse,
    )
        .into_response()
}

/// OpenAI Responses API locked response
fn openai_responses(is_stream: bool, message: &str) -> Response {
    let content = message;
    let now = now_secs();
    let resp_id = format!("resp_locked_{}", now);
    let msg_id_val = format!("msg_locked_{}", now);

    let output_item = serde_json::json!({
        "type": "message", "id": msg_id_val, "role": "assistant", "status": "completed",
        "content": [{ "type": "output_text", "text": content, "annotations": [] }],
    });
    let full_response = serde_json::json!({
        "id": resp_id, "object": "response", "created_at": now, "status": "completed",
        "model": "gpt-4o", "output": [output_item],
        "usage": { "input_tokens": 0, "output_tokens": 0, "total_tokens": 0 },
    });

    if !is_stream {
        let body = serde_json::to_string(&full_response).unwrap_or_default();
        return (StatusCode::OK, [("content-type", "application/json")], body).into_response();
    }

    let sse = format!(
        "event: response.created\ndata: {}\n\nevent: response.completed\ndata: {}\n\n",
        serde_json::to_string(&full_response).unwrap_or_default(),
        serde_json::to_string(&full_response).unwrap_or_default(),
    );

    (
        StatusCode::OK,
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
            ("connection", "keep-alive"),
        ],
        sse,
    )
        .into_response()
}

/// Google Gemini locked response
fn gemini(message: &str) -> Response {
    let content = message;
    let body = serde_json::to_string(&serde_json::json!({
        "candidates": [{
            "content": { "parts": [{ "text": content }], "role": "model" },
            "finishReason": "STOP", "index": 0,
        }],
        "usageMetadata": {
            "promptTokenCount": 0, "candidatesTokenCount": 0, "totalTokenCount": 0
        },
    }))
    .unwrap_or_default();
    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn custom_message_appears_in_openai_response() {
        let resp = render_for_upstream(
            "https://api.openai.com/v1",
            false,
            "https://admin.example.com",
            Some("Custom locked text here"),
        ).unwrap();
        let body = body_string(resp).await;
        assert!(body.contains("Custom locked text here"), "body: {}", body);
        // Should NOT contain the default message
        assert!(!body.contains("vault is locked"), "body: {}", body);
    }

    #[tokio::test]
    async fn none_message_uses_default() {
        let resp = render_for_upstream(
            "https://api.openai.com/v1",
            false,
            "https://admin.example.com",
            None,
        ).unwrap();
        let body = body_string(resp).await;
        assert!(body.contains("vault is locked"), "body: {}", body);
        assert!(body.contains("admin.example.com"), "body: {}", body);
    }

    #[tokio::test]
    async fn anthropic_url_uses_anthropic_format() {
        let resp = render_for_upstream(
            "https://api.anthropic.com/v1",
            false,
            "https://x.com",
            Some("locked"),
        ).unwrap();
        let body = body_string(resp).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        // Anthropic format has "type": "message"
        assert_eq!(json["type"], "message");
        assert_eq!(json["content"][0]["type"], "text");
    }

    #[tokio::test]
    async fn openai_url_uses_openai_format() {
        let resp = render_for_upstream(
            "https://api.openai.com/v1",
            false,
            "https://x.com",
            Some("locked"),
        ).unwrap();
        let body = body_string(resp).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["object"], "chat.completion");
    }

    #[tokio::test]
    async fn gemini_url_uses_gemini_format() {
        let resp = render_for_upstream(
            "https://generativelanguage.googleapis.com/v1",
            false,
            "https://x.com",
            Some("locked"),
        ).unwrap();
        let body = body_string(resp).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json["candidates"].is_array());
    }

    #[tokio::test]
    async fn deepseek_uses_openai_format() {
        let resp = render_for_upstream(
            "https://api.deepseek.com/v1",
            false,
            "https://x.com",
            Some("msg"),
        ).unwrap();
        let body = body_string(resp).await;
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["object"], "chat.completion");
    }

    #[tokio::test]
    async fn streaming_anthropic_uses_sse() {
        let resp = render_for_upstream(
            "https://api.anthropic.com/v1",
            true,
            "https://x.com",
            Some("stream msg"),
        ).unwrap();
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
        let body = body_string(resp).await;
        assert!(body.contains("event: message_start"), "body: {}", body);
        assert!(body.contains("stream msg"), "body: {}", body);
    }

    #[tokio::test]
    async fn render_legacy_template_works() {
        let resp = render("openai", false, "https://x.com").unwrap();
        let body = body_string(resp).await;
        assert!(body.contains("vault is locked"));
    }

    #[tokio::test]
    async fn render_unknown_template_returns_none() {
        assert!(render("unknown_format", false, "https://x.com").is_none());
    }
}
