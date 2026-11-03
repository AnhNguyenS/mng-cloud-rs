//! Authorization helpers.
//!
//! Authentication answers *who* the caller is; this module answers *what* that
//! caller may read. Roles are derived from the freshly loaded `users` row on
//! every request, never from a client cookie, so deactivating an account or
//! removing admin rights takes effect immediately.
//!
//! Administrative access only opens administrative metadata routes. It never
//! grants access to another user's item rows: those are the metadata of an
//! encrypted library and remain owner-only.

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use mng_db::User;

use crate::{auth::AuthenticatedUser, http::json_error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn from_user(user: &User) -> Self {
        if user.is_admin {
            Self::Admin
        } else {
            Self::User
        }
    }

    pub fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

/// The only owner id a normal read handler may use. Admin rights are
/// deliberately excluded: there is no cross-user item override.
pub fn item_owner_id(authenticated: &AuthenticatedUser) -> i64 {
    authenticated.user.id
}

/// Middleware for `/api/v1/admin/*`. It must run after `require_session`, which
/// inserts [`AuthenticatedUser`] into the request extensions.
pub async fn require_admin(request: Request, next: Next) -> Response {
    let Some(authenticated) = request.extensions().get::<AuthenticatedUser>() else {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            Some("Phiên đăng nhập đã hết hạn.".to_owned()),
        );
    };
    if !Role::from_user(&authenticated.user).is_admin() {
        return json_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            Some("Chỉ quản trị viên mới được thực hiện thao tác này.".to_owned()),
        );
    }
    next.run(request).await
}
