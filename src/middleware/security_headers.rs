use axum::{body::Body, http::Request, middleware::Next, response::Response};

pub async fn layer(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

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
        "default-src 'self'; script-src 'self' https://unpkg.com https://analytics.osmosis.page 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://static.layer55.eu; connect-src 'self' https://analytics.osmosis.page; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );

    response
}
