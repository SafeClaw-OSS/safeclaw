/// Locked proxy response generators (by template name).
///
/// When the vault is locked, the proxy returns API-format-aware placeholder
/// responses. Template names come from service.toml `[upstream.locked]`.
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Render a locked response by template name.
pub fn render(template: &str, is_stream: bool, admin_url: &str) -> Option<Response> {
    match template {
        "anthropic" => Some(anthropic(is_stream, admin_url)),
        "openai" => Some(openai(is_stream, admin_url)),
        "openai-responses" => Some(openai_responses(is_stream, admin_url)),
        "gemini" => Some(gemini(admin_url)),
        _ => None,
    }
}

fn locked_message(admin_url: &str) -> String {
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
fn anthropic(is_stream: bool, admin_url: &str) -> Response {
    let content = locked_message(admin_url);
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
fn openai(is_stream: bool, admin_url: &str) -> Response {
    let content = locked_message(admin_url);
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
            "safeclaw_locked": true,
            "safeclaw_unlock_url": admin_url,
            "safeclaw_buttons": [[{ "text": "🔓 Unlock SafeClaw", "url": admin_url }]],
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
fn openai_responses(is_stream: bool, admin_url: &str) -> Response {
    let content = locked_message(admin_url);
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
fn gemini(admin_url: &str) -> Response {
    let content = locked_message(admin_url);
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
