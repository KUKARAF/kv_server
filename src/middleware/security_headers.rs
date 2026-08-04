use axum::{body::Body, http::Request, middleware::Next, response::Response};

pub async fn layer(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Every value here is a hardcoded, valid-ASCII string literal, so
    // parsing to `HeaderValue` cannot fail.
    #[allow(clippy::unwrap_used)]
    {
        headers.insert(
            "strict-transport-security",
            "max-age=63072000; includeSubDomains".parse().unwrap(),
        );
        headers.insert("x-frame-options", "DENY".parse().unwrap());
        headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        headers.insert(
            "referrer-policy",
            "strict-origin-when-cross-origin".parse().unwrap(),
        );
        headers.insert(
            "content-security-policy",
            "default-src 'self'; script-src 'self' https://unpkg.com https://analytics.osmosis.page 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://static.osmosis.page; connect-src 'self' https://analytics.osmosis.page https://openrouter.ai; frame-ancestors 'none'"
                .parse()
                .unwrap(),
        );
    }

    response
}
