//! Embedded user interface (Svelte build in `ui-dist/`). Unknown paths
//! deliver `index.html`, the app routes by itself.

use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use rust_embed::{Embed, RustEmbed};

#[derive(Embed)]
#[folder = "ui-dist/"]
struct Assets;

pub fn router() -> Router {
    embedded::<Assets>()
}

/// Serves another build of the dashboard, with the same headers.
pub fn embedded<E: RustEmbed + Send + Sync + 'static>() -> Router {
    Router::new().fallback(serve::<E>)
}

async fn serve<E: RustEmbed>(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match E::get(path) {
        Some(f) => file(path, f.data.into_owned(), path != "index.html" && path.starts_with("assets/")),
        None => match E::get("index.html") {
            Some(f) => file("index.html", f.data.into_owned(), false),
            None => (StatusCode::NOT_FOUND, "user interface not embedded (ui-dist missing)").into_response(),
        },
    }
}

fn file(path: &str, data: Vec<u8>, immutable: bool) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let cache = if immutable { "public, max-age=31536000, immutable" } else { "no-cache" };
    Response::builder()
        .header(header::CONTENT_TYPE, mime.as_ref())
        .header(header::CACHE_CONTROL, cache)
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "same-origin")
        .header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        .body(Body::from(data))
        .unwrap()
}
