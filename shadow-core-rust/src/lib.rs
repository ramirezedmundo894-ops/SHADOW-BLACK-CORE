use hyper::body::HttpBody;
use hyper::client::HttpConnector;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode, Uri};
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    Python,
    Go,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub method: Method,
    pub path: &'static str,
    pub backend: Backend,
    pub backend_path: &'static str,
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub python_upstream: Uri,
    pub go_upstream: Option<Uri>,
    pub go_proxy_token: Option<String>,
    pub go_internal_token: Option<String>,
    pub trusted_proxies: Vec<IpAddr>,
    pub max_body_bytes: usize,
    pub rate_limit_requests: usize,
    pub rate_limit_window: Duration,
    pub rate_limit_max_clients: usize,
}

impl ProxyConfig {
    pub fn from_env() -> Result<Self, String> {
        let python_upstream = parse_upstream(
            &env::var("SHADOW_PYTHON_UPSTREAM").unwrap_or_else(|_| "http://127.0.0.1:8000".into()),
        )?;
        let go_upstream_raw = env::var("SHADOW_GO_UPSTREAM")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let go_upstream = go_upstream_raw
            .map(|value| parse_upstream(&value))
            .transpose()?;
        let go_proxy_token = env::var("SHADOW_GO_PROXY_TOKEN")
            .ok()
            .filter(|v| !v.is_empty());
        let go_internal_token = env::var("SHADOW_GO_INTERNAL_TOKEN")
            .ok()
            .filter(|v| !v.is_empty());
        if go_upstream.is_some() && (go_proxy_token.is_none() || go_internal_token.is_none()) {
            return Err(
                "SHADOW_GO_UPSTREAM requires SHADOW_GO_PROXY_TOKEN and SHADOW_GO_INTERNAL_TOKEN"
                    .into(),
            );
        }
        let trusted_proxies = env::var("SHADOW_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<IpAddr>()
                    .map_err(|_| format!("invalid trusted proxy IP: {s}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            python_upstream,
            go_upstream,
            go_proxy_token,
            go_internal_token,
            trusted_proxies,
            max_body_bytes: parse_env("SHADOW_MAX_BODY_BYTES", 1_048_576usize)?,
            rate_limit_requests: parse_env("SHADOW_RATE_LIMIT_REQUESTS", 120usize)?,
            rate_limit_window: Duration::from_secs(parse_env(
                "SHADOW_RATE_LIMIT_WINDOW_SECONDS",
                60u64,
            )?),
            rate_limit_max_clients: parse_env("SHADOW_RATE_LIMIT_MAX_CLIENTS", 20_000usize)?,
        })
    }

    pub fn routes(&self) -> Vec<Route> {
        let mut routes = vec![
            route(
                Method::POST,
                "/api/auth/token",
                Backend::Python,
                "/api/auth/token",
            ),
            route(
                Method::POST,
                "/api/auth/refresh",
                Backend::Python,
                "/api/auth/refresh",
            ),
            route(
                Method::POST,
                "/api/auth/revoke",
                Backend::Python,
                "/api/auth/revoke",
            ),
            route(
                Method::POST,
                "/api/attestation/challenges",
                Backend::Python,
                "/api/attestation/challenges",
            ),
            route(
                Method::POST,
                "/api/attestation/verify",
                Backend::Python,
                "/api/attestation/verify",
            ),
            route(
                Method::POST,
                "/api/decision",
                Backend::Python,
                "/api/decision",
            ),
            route(
                Method::POST,
                "/api/analysis/beaconing",
                Backend::Python,
                "/api/analysis/beaconing",
            ),
            route(
                Method::GET,
                "/api/evidence",
                Backend::Python,
                "/api/evidence",
            ),
            route(
                Method::GET,
                "/api/evidence/verify",
                Backend::Python,
                "/api/evidence/verify",
            ),
            route(
                Method::POST,
                "/api/improvement-actions",
                Backend::Python,
                "/api/improvement-actions",
            ),
        ];
        if self.go_upstream.is_some() {
            routes.push(route(
                Method::POST,
                "/internal/v1/decision",
                Backend::Go,
                "/v1/decision",
            ));
        }
        routes
    }
}

fn route(
    method: Method,
    path: &'static str,
    backend: Backend,
    backend_path: &'static str,
) -> Route {
    Route {
        method,
        path,
        backend,
        backend_path,
    }
}

fn parse_upstream(value: &str) -> Result<Uri, String> {
    let uri = value
        .parse::<Uri>()
        .map_err(|_| format!("invalid upstream URI: {value}"))?;
    if uri.scheme_str() != Some("http") || uri.authority().is_none() || uri.path() != "/" {
        return Err(
            "upstream must be an http:// URI with host and optional port, without a path".into(),
        );
    }
    Ok(uri)
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|_| format!("invalid {name}")),
        Err(_) => Ok(default),
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, Window>>>,
    limit: usize,
    window: Duration,
    max_clients: usize,
}

#[derive(Clone, Copy)]
struct Window {
    started: Instant,
    count: usize,
}

impl RateLimiter {
    pub fn new(limit: usize, window: Duration, max_clients: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            limit,
            window,
            max_clients,
        }
    }

    pub fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        let Ok(mut entries) = self.inner.lock() else {
            return false;
        };
        if let Some(entry) = entries.get_mut(&ip) {
            if now.saturating_duration_since(entry.started) >= self.window {
                *entry = Window {
                    started: now,
                    count: 1,
                };
                return true;
            }
            if entry.count >= self.limit {
                return false;
            }
            entry.count += 1;
            return true;
        }
        if entries.len() >= self.max_clients {
            entries.retain(|_, value| now.saturating_duration_since(value.started) < self.window);
            if entries.len() >= self.max_clients {
                return false;
            }
        }
        entries.insert(
            ip,
            Window {
                started: now,
                count: 1,
            },
        );
        true
    }
}

#[derive(Clone)]
struct ProxyState {
    config: Arc<ProxyConfig>,
    routes: Arc<Vec<Route>>,
    client: Client<HttpConnector, Body>,
    limiter: RateLimiter,
}

impl ProxyState {
    fn new(config: ProxyConfig) -> Self {
        let limiter = RateLimiter::new(
            config.rate_limit_requests,
            config.rate_limit_window,
            config.rate_limit_max_clients,
        );
        let routes = config.routes();
        Self {
            config: Arc::new(config),
            routes: Arc::new(routes),
            client: Client::new(),
            limiter,
        }
    }
}

pub fn sanitized_headers(
    incoming: &HeaderMap,
    request_id: &str,
    client_ip: IpAddr,
    go_internal_token: Option<&str>,
) -> HeaderMap {
    let mut output = HeaderMap::new();
    for key in [
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::USER_AGENT,
    ] {
        if let Some(value) = incoming.get(&key) {
            output.insert(key, value.clone());
        }
    }
    let idempotency_key = HeaderName::from_static("idempotency-key");
    if let Some(value) = incoming.get(&idempotency_key) {
        output.insert(idempotency_key, value.clone());
    }
    output.insert(
        HeaderName::from_static("x-shadow-request-id"),
        HeaderValue::from_str(request_id).expect("UUID is a valid header value"),
    );
    output.insert(
        HeaderName::from_static("x-real-ip"),
        HeaderValue::from_str(&client_ip.to_string()).expect("IP is a valid header value"),
    );
    if let Some(token) = go_internal_token {
        if let Ok(value) = HeaderValue::from_str(token) {
            output.insert(HeaderName::from_static("x-shadow-internal-token"), value);
        }
    }
    output
}

fn client_ip(peer_ip: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> IpAddr {
    if trusted_proxies.contains(&peer_ip) {
        if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = value.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    peer_ip
}

fn go_proxy_authorized(headers: &HeaderMap, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(provided) = value.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_equal(provided.as_bytes(), expected.as_bytes())
}

fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

fn response(status: StatusCode, body: &'static str, request_id: Option<&str>) -> Response<Body> {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8");
    if let Some(id) = request_id {
        builder = builder.header("x-shadow-request-id", id);
    }
    builder
        .body(Body::from(body))
        .expect("static response builds")
}

async fn read_bounded(mut body: Body, max: usize) -> Result<Body, ()> {
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| ())?;
        if bytes.len().saturating_add(chunk.len()) > max {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Body::from(bytes))
}

fn build_upstream_uri(upstream: &Uri, path: &str, query: Option<&str>) -> Result<Uri, ()> {
    let authority = upstream.authority().ok_or(())?.as_str();
    let suffix = query
        .map(|q| format!("{path}?{q}"))
        .unwrap_or_else(|| path.to_string());
    format!("http://{authority}{suffix}")
        .parse()
        .map_err(|_| ())
}

async fn handle_request(
    mut req: Request<Body>,
    peer_ip: IpAddr,
    state: ProxyState,
) -> Result<Response<Body>, Infallible> {
    let request_id = Uuid::new_v4().to_string();
    if req.method() == Method::GET && req.uri().path() == "/health" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-shadow-request-id", &request_id)
            .body(Body::from(
                "{\"status\":\"ok\",\"service\":\"shadow-core-rust-proxy\"}",
            ))
            .expect("health response builds"));
    }
    let path = req.uri().path();
    let Some(route) = state
        .routes
        .iter()
        .find(|route| route.method == *req.method() && route.path == path)
        .cloned()
    else {
        return Ok(response(
            StatusCode::NOT_FOUND,
            "route not allowed",
            Some(&request_id),
        ));
    };
    let effective_ip = client_ip(peer_ip, req.headers(), &state.config.trusted_proxies);
    if !state.limiter.allow_at(effective_ip, Instant::now()) {
        return Ok(response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
            Some(&request_id),
        ));
    }
    let target = match route.backend {
        Backend::Python => &state.config.python_upstream,
        Backend::Go => match state.config.go_upstream.as_ref() {
            Some(uri) => uri,
            None => {
                return Ok(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Go backend unavailable",
                    Some(&request_id),
                ))
            }
        },
    };
    if route.backend == Backend::Go
        && !go_proxy_authorized(req.headers(), state.config.go_proxy_token.as_deref())
    {
        return Ok(response(
            StatusCode::UNAUTHORIZED,
            "internal route unauthorized",
            Some(&request_id),
        ));
    }
    if req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .map(|size| size > state.config.max_body_bytes)
        .unwrap_or(false)
    {
        return Ok(response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
            Some(&request_id),
        ));
    }
    let body = match read_bounded(
        std::mem::replace(req.body_mut(), Body::empty()),
        state.config.max_body_bytes,
    )
    .await
    {
        Ok(body) => body,
        Err(_) => {
            return Ok(response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
                Some(&request_id),
            ))
        }
    };
    let headers = sanitized_headers(
        req.headers(),
        &request_id,
        effective_ip,
        if route.backend == Backend::Go {
            state.config.go_internal_token.as_deref()
        } else {
            None
        },
    );
    let uri = match build_upstream_uri(target, route.backend_path, req.uri().query()) {
        Ok(uri) => uri,
        Err(_) => {
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "invalid backend route",
                Some(&request_id),
            ))
        }
    };
    let mut builder = Request::builder().method(req.method()).uri(uri);
    *builder.headers_mut().expect("request builder headers") = headers;
    let upstream_request = match builder.body(body) {
        Ok(request) => request,
        Err(_) => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "invalid request",
                Some(&request_id),
            ))
        }
    };
    let upstream_response = match state.client.request(upstream_request).await {
        Ok(response) => response,
        Err(_) => {
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "backend unavailable",
                Some(&request_id),
            ))
        }
    };
    let status = upstream_response.status();
    let mut response_headers = HeaderMap::new();
    for key in [
        header::CONTENT_TYPE,
        header::CACHE_CONTROL,
        header::RETRY_AFTER,
        header::WWW_AUTHENTICATE,
    ] {
        if let Some(value) = upstream_response.headers().get(&key) {
            response_headers.insert(key, value.clone());
        }
    }
    let response_body =
        match read_bounded(upstream_response.into_body(), state.config.max_body_bytes).await {
            Ok(body) => body,
            Err(_) => {
                return Ok(response(
                    StatusCode::BAD_GATEWAY,
                    "backend response too large or unreadable",
                    Some(&request_id),
                ))
            }
        };
    let mut output = Response::builder().status(status);
    *output.headers_mut().expect("response builder headers") = response_headers;
    output = output.header("x-shadow-request-id", request_id);
    Ok(output
        .body(response_body)
        .unwrap_or_else(|_| response(StatusCode::BAD_GATEWAY, "response build failed", None)))
}

pub async fn serve(config: ProxyConfig, addr: SocketAddr) -> Result<(), hyper::Error> {
    let state = ProxyState::new(config);
    let make = make_service_fn(move |connection: &hyper::server::conn::AddrStream| {
        let state = state.clone();
        let peer_ip = connection.remote_addr().ip();
        async move {
            Ok::<_, Infallible>(service_fn(move |request| {
                handle_request(request, peer_ip, state.clone())
            }))
        }
    });
    Server::bind(&addr).serve(make).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config(python: Uri) -> ProxyConfig {
        ProxyConfig {
            python_upstream: python,
            go_upstream: None,
            go_proxy_token: None,
            go_internal_token: None,
            trusted_proxies: vec![],
            max_body_bytes: 8,
            rate_limit_requests: 100,
            rate_limit_window: Duration::from_secs(60),
            rate_limit_max_clients: 100,
        }
    }

    async fn start_server<F, Fut>(handler: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: Fn(Request<Body>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Response<Body>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let service = make_service_fn(move |_| {
            let handler = handler.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(req).await) }
                }))
            }
        });
        let server = Server::try_bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .unwrap()
            .serve(service);
        let addr = server.local_addr();
        let task = tokio::spawn(async move {
            let _ = server.await;
        });
        (addr, task)
    }

    #[test]
    fn allowlist_has_only_exact_methods_and_paths() {
        let cfg = config("http://127.0.0.1:8000".parse().unwrap());
        let routes = cfg.routes();
        assert!(routes
            .iter()
            .any(|r| r.method == Method::POST && r.path == "/api/decision"));
        assert!(!routes.iter().any(|r| r.path == "/api/unknown"));
        assert!(!routes
            .iter()
            .any(|r| r.method == Method::GET && r.path == "/api/decision"));
        assert!(!routes.iter().any(|r| r.path == "/v1/decision"));
    }

    #[test]
    fn limiter_rejects_over_limit_and_resets_window() {
        let limiter = RateLimiter::new(2, Duration::from_secs(10), 4);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let start = Instant::now();
        assert!(limiter.allow_at(ip, start));
        assert!(limiter.allow_at(ip, start + Duration::from_secs(1)));
        assert!(!limiter.allow_at(ip, start + Duration::from_secs(2)));
        assert!(limiter.allow_at(ip, start + Duration::from_secs(10)));
    }

    #[test]
    fn client_ip_ignores_forwarded_headers_unless_peer_is_trusted() {
        let peer: IpAddr = "192.0.2.10".parse().unwrap();
        let spoof: IpAddr = "203.0.113.9".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.9"));
        assert_eq!(client_ip(peer, &headers, &[]), peer);
        assert_eq!(client_ip(peer, &headers, &[peer]), spoof);
    }

    #[test]
    fn sanitization_drops_untrusted_internal_identity_headers_and_replaces_ip() {
        let mut incoming = HeaderMap::new();
        incoming.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer user-token"),
        );
        incoming.insert(
            HeaderName::from_static("idempotency-key"),
            HeaderValue::from_static("idempotency-1"),
        );
        incoming.insert(
            "x-shadow-internal-token",
            HeaderValue::from_static("attacker-value"),
        );
        incoming.insert("x-authenticated-user", HeaderValue::from_static("admin"));
        incoming.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.1"));
        incoming.insert("x-shadow-request-id", HeaderValue::from_static("chosen-id"));
        let forwarded_ip: IpAddr = "192.0.2.4".parse().unwrap();
        let headers = sanitized_headers(&incoming, "server-generated-id", forwarded_ip, None);
        assert_eq!(
            headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer user-token"
        );
        assert_eq!(
            headers
                .get(HeaderName::from_static("idempotency-key"))
                .unwrap(),
            "idempotency-1"
        );
        assert_eq!(
            headers.get("x-shadow-request-id").unwrap(),
            "server-generated-id"
        );
        assert_eq!(headers.get("x-real-ip").unwrap(), "192.0.2.4");
        assert!(headers.get("x-shadow-internal-token").is_none());
        assert!(headers.get("x-authenticated-user").is_none());
        assert!(headers.get("x-forwarded-for").is_none());
    }

    #[tokio::test]
    async fn health_is_local_and_does_not_need_backend() {
        let state = ProxyState::new(config("http://127.0.0.1:1".parse().unwrap()));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let response = handle_request(req, IpAddr::V4(Ipv4Addr::LOCALHOST), state)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("x-shadow-request-id"));
        let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        assert!(String::from_utf8(bytes.to_vec())
            .unwrap()
            .contains("shadow-core-rust-proxy"));
    }

    #[tokio::test]
    async fn rejects_oversized_payload_before_forwarding() {
        let hits = Arc::new(AtomicUsize::new(0));
        let backend_hits = hits.clone();
        let (addr, task) = start_server(move |_req| {
            let hits = backend_hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                Response::new(Body::from("unexpected"))
            }
        })
        .await;
        let mut cfg = config(format!("http://{addr}").parse().unwrap());
        cfg.max_body_bytes = 4;
        let state = ProxyState::new(cfg);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/decision")
            .body(Body::from("12345"))
            .unwrap();
        let response = handle_request(req, IpAddr::V4(Ipv4Addr::LOCALHOST), state)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn forwards_only_allowed_route_and_safe_headers() {
        let seen = Arc::new(Mutex::new(None::<(String, HeaderMap, Vec<u8>)>));
        let backend_seen = seen.clone();
        let (addr, task) = start_server(move |req| {
            let seen = backend_seen.clone();
            async move {
                let path = req.uri().path().to_owned();
                let headers = req.headers().clone();
                let body = hyper::body::to_bytes(req.into_body())
                    .await
                    .unwrap()
                    .to_vec();
                *seen.lock().unwrap() = Some((path, headers, body));
                Response::builder()
                    .status(StatusCode::CREATED)
                    .body(Body::from("ok"))
                    .unwrap()
            }
        })
        .await;
        let state = ProxyState::new(config(format!("http://{addr}").parse().unwrap()));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/decision?mode=test")
            .header(header::AUTHORIZATION, "Bearer user-token")
            .header(HeaderName::from_static("idempotency-key"), "key-123")
            .header("x-shadow-internal-token", "fake-secret")
            .header("x-authenticated-user", "admin")
            .header("x-forwarded-for", "203.0.113.4")
            .header("x-shadow-request-id", "client-picked")
            .body(Body::from("data"))
            .unwrap();
        let response = handle_request(req, IpAddr::V4(Ipv4Addr::LOCALHOST), state)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().contains_key("x-shadow-request-id"));
        let captured = seen.lock().unwrap().clone().unwrap();
        assert_eq!(captured.0, "/api/decision");
        assert_eq!(
            captured.1.get(header::AUTHORIZATION).unwrap(),
            "Bearer user-token"
        );
        assert_eq!(
            captured
                .1
                .get(HeaderName::from_static("idempotency-key"))
                .unwrap(),
            "key-123"
        );
        assert!(captured.1.get("x-shadow-internal-token").is_none());
        assert!(captured.1.get("x-authenticated-user").is_none());
        assert!(captured.1.get("x-forwarded-for").is_none());
        assert_eq!(captured.1.get("x-real-ip").unwrap(), "127.0.0.1");
        assert!(
            captured
                .1
                .get("x-shadow-request-id")
                .unwrap()
                .to_str()
                .unwrap()
                != "client-picked"
        );
        assert_eq!(captured.2, b"data");
        task.abort();
    }

    #[tokio::test]
    async fn go_route_is_disabled_by_default_and_requires_proxy_token_when_enabled() {
        let mut cfg = config("http://127.0.0.1:8000".parse().unwrap());
        assert!(!cfg
            .routes()
            .iter()
            .any(|r| r.path == "/internal/v1/decision"));
        cfg.go_upstream = Some("http://127.0.0.1:8081".parse().unwrap());
        cfg.go_proxy_token = Some("service-secret-for-proxy-route".into());
        cfg.go_internal_token = Some("internal-go-token-secret".into());
        let state = ProxyState::new(cfg);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/internal/v1/decision")
            .body(Body::empty())
            .unwrap();
        let response = handle_request(req, IpAddr::V4(Ipv4Addr::LOCALHOST), state)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
