//! Small JSON response helpers shared by the authentication, RBAC and read
//! handlers. Every API error has the same `{ ok: false, error, message? }`
//! shape so the browser adapter can handle it uniformly.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub fn json_error(status: StatusCode, code: &'static str, message: Option<String>) -> Response {
    let mut body = json!({ "ok": false, "error": code });
    if let Some(message) = message {
        body["message"] = json!(message);
    }
    (status, Json(body)).into_response()
}
