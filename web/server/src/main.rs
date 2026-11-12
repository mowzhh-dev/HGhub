//! HGhub 网页版服务。
//!
//! 设计要点：
//! - 业务、解密、线路、媒体代理全部复用 `src-tauri/src/*.rs` 原文件（#[path] 引入，零改动）；
//!   前端原来 `invoke(cmd, args)` 调原生层，网页版改成 `POST /api/invoke/<cmd>`。
//! - 原来的 `hg://` 自定义协议换成 `GET /m/<媒体令牌>/{img,hls,seg}?u=`，
//!   m3u8 里的 key / 分片地址也被改写到这个前缀下。
//! - 密码登录门：除 /login 外全部需要会话；媒体地址里的令牌与会话绑定，
//!   这样 iOS 原生 HLS 拉分片时即使不带 Cookie 也能鉴权。
//! - 严格安全模式锁死开启：代理不会被用来访问内网（网络策略在 network_policy.rs）。
#![allow(dead_code, unused_imports)]

#[path = "../../../src-tauri/src/api.rs"]
mod api;
#[path = "../../../src-tauri/src/lines.rs"]
mod lines;
#[path = "../../../src-tauri/src/logging.rs"]
mod logging;
#[path = "../../../src-tauri/src/media.rs"]
mod media;
#[path = "../../../src-tauri/src/net.rs"]
mod net;
#[path = "../../../src-tauri/src/network_policy.rs"]
mod network_policy;
#[path = "../../../src-tauri/src/playback_log.rs"]
mod playback_log;
#[path = "../../../src-tauri/src/session.rs"]
mod session;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Request, State as AxState};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, State};
use tower_http::services::ServeDir;

static API: Lazy<api::Api> = Lazy::new(api::Api::new);

const COOKIE: &str = "hg_sess";
const SESSION_TTL: u64 = 30 * 24 * 3600;
const MAX_FAILS: u32 = 8;
const FAIL_WINDOW: u64 = 15 * 60;

/* ───────────────────────── 配置 ───────────────────────── */

struct Config {
    bind: SocketAddr,
    data: PathBuf,
    dist: PathBuf,
    password_hash: String,
    cookie_secure: bool,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| default.to_string())
}

/* ───────────────────────── 会话 ───────────────────────── */

#[derive(Clone, Serialize, Deserialize)]
struct WebSession {
    /// 媒体令牌：出现在 /m/<mtok>/… 地址里
    mtok: String,
    expires: u64,
}

struct AppState {
    cfg: Config,
    sessions: Mutex<HashMap<String, WebSession>>,
    fails: Mutex<HashMap<IpAddr, (u32, u64)>>,
    index_html: String,
}

type Shared = Arc<AppState>;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("system RNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl AppState {
    fn sessions_file(&self) -> PathBuf {
        self.cfg.data.join("web-sessions.json")
    }

    fn load_sessions(&self) {
        if let Ok(text) = std::fs::read_to_string(self.sessions_file()) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, WebSession>>(&text) {
                let t = now();
                *self.sessions.lock().unwrap() =
                    map.into_iter().filter(|(_, s)| s.expires > t).collect();
            }
        }
    }

    fn persist_sessions(&self) {
        let snapshot = self.sessions.lock().unwrap().clone();
        if let Ok(text) = serde_json::to_string(&snapshot) {
            let path = self.sessions_file();
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(tmp, path);
            }
        }
    }

    fn session_for_cookie(&self, headers: &HeaderMap) -> Option<WebSession> {
        let sid = cookie_value(headers, COOKIE)?;
        let t = now();
        self.sessions.lock().unwrap().get(&sid).filter(|s| s.expires > t).cloned()
    }

    fn mtok_valid(&self, mtok: &str) -> bool {
        if mtok.len() != 32 {
            return false;
        }
        let t = now();
        self.sessions.lock().unwrap().values().any(|s| s.mtok == mtok && s.expires > t)
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(|raw| {
        raw.split(';').find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name && !v.is_empty()).then(|| v.to_string())
        })
    })
}

/// 客户端 IP：只在对端是本机（nginx 反代）时信任 X-Real-IP。
fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if peer.ip().is_loopback() {
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

fn security_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    h.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
}

/* ───────────────────────── 登录门 ───────────────────────── */

const LOGIN_HTML: &str = r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>登录</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#1a1a1a;color:#eee;font:16px -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;padding:16px}
form{width:100%;max-width:320px;display:flex;flex-direction:column;gap:12px}
h1{font-size:20px;font-weight:600;margin:0 0 8px}
input{font-size:17px;padding:12px 14px;border-radius:10px;border:1px solid #333;background:#262626;color:#eee;outline:none}
input:focus{border-color:#f5a623}
button{font-size:17px;padding:12px;border:0;border-radius:10px;background:#f5a623;color:#1a1a1a;font-weight:600}
.err{color:#ff6b6b;font-size:14px;min-height:1em}
</style></head><body>
<form method="post" action="/login" autocomplete="on">
<h1>请输入访问密码</h1>
<input type="password" name="password" autocomplete="current-password" required autofocus>
<div class="err">__ERR__</div>
<button type="submit">进入</button>
</form></body></html>"#;

fn login_page(err: &str, status: StatusCode) -> Response {
    let mut resp = (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        LOGIN_HTML.replace("__ERR__", err),
    )
        .into_response();
    security_headers(&mut resp);
    resp
}

async fn login_get(AxState(st): AxState<Shared>, headers: HeaderMap) -> Response {
    if st.session_for_cookie(&headers).is_some() {
        return Redirect::to("/").into_response();
    }
    login_page("", StatusCode::OK)
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login_post(
    AxState(st): AxState<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = client_ip(peer, &headers);
    let t = now();
    {
        let mut fails = st.fails.lock().unwrap();
        fails.retain(|_, (_, since)| t.saturating_sub(*since) < FAIL_WINDOW);
        if fails.get(&ip).is_some_and(|(n, _)| *n >= MAX_FAILS) {
            return login_page("尝试次数过多，请 15 分钟后再试", StatusCode::TOO_MANY_REQUESTS);
        }
    }
    let ok = PasswordHash::new(&st.cfg.password_hash)
        .map(|h| Argon2::default().verify_password(form.password.as_bytes(), &h).is_ok())
        .unwrap_or(false);
    if !ok {
        {
            let mut fails = st.fails.lock().unwrap();
            let e = fails.entry(ip).or_insert((0, t));
            e.0 += 1;
        }
        eprintln!("[auth] login failed from {ip}");
        tokio::time::sleep(Duration::from_millis(800)).await;
        return login_page("密码不对", StatusCode::UNAUTHORIZED);
    }
    st.fails.lock().unwrap().remove(&ip);
    let sid = random_hex(32);
    st.sessions.lock().unwrap().insert(
        sid.clone(),
        WebSession { mtok: random_hex(16), expires: t + SESSION_TTL },
    );
    st.persist_sessions();
    eprintln!("[auth] login ok from {ip}");
    let cookie = format!(
        "{COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}{}",
        if st.cfg.cookie_secure { "; Secure" } else { "" }
    );
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

async fn logout(AxState(st): AxState<Shared>, headers: HeaderMap) -> Response {
    if let Some(sid) = cookie_value(&headers, COOKIE) {
        st.sessions.lock().unwrap().remove(&sid);
        st.persist_sessions();
    }
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("hg_sess=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    resp
}

/// 鉴权中间件：/login 与 /m/<令牌>/… 自行处理，其余一律要求有效会话。
async fn require_session(AxState(st): AxState<Shared>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path == "/login" || path.starts_with("/m/") {
        let mut r = next.run(req).await;
        security_headers(&mut r);
        return r;
    }
    if st.session_for_cookie(req.headers()).is_none() {
        if path.starts_with("/api/") {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "未登录"}))).into_response();
        }
        return Redirect::to("/login").into_response();
    }
    let mut r = next.run(req).await;
    security_headers(&mut r);
    r
}

/* ───────────────────────── 页面 ───────────────────────── */

async fn index(AxState(st): AxState<Shared>, headers: HeaderMap) -> Response {
    let Some(sess) = st.session_for_cookie(&headers) else {
        return Redirect::to("/login").into_response();
    };
    let inject = format!(
        "<script>window.__HG_LOCAL__=\"/m/{}\";</script>\n<link rel=\"apple-touch-icon\" href=\"/apple-touch-icon.png\">\n</head>",
        sess.mtok
    );
    let html = st.index_html.replacen("</head>", &inject, 1);
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        html,
    )
        .into_response()
}

/* ───────────────────────── invoke → HTTP ───────────────────────── */

fn arg<T: serde::de::DeserializeOwned>(args: &Value, key: &str) -> Result<T, String> {
    serde_json::from_value(args.get(key).cloned().unwrap_or(Value::Null))
        .map_err(|e| format!("参数 {key} 无效：{e}"))
}

fn to_json<T: Serialize>(v: T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

async fn dispatch(cmd: &str, a: &Value) -> Result<Value, String> {
    let st = || State::new(&*API);
    let app = AppHandle;
    match cmd {
        "app_boot" => api::app_boot(st()).await,
        // 网页版锁死严格模式：不允许关闭网络守卫（否则媒体代理可被用来访问服务器内网）
        "security_set" => Ok(json!(network_policy::strict_security())),
        "debug_log" => {
            let msg: String = arg(a, "msg")?;
            let msg: String = msg.chars().take(2000).collect();
            api::debug_log(app, msg).await.map(|_| Value::Null)
        }
        "net_diag" => api::net_diag().await,
        "line_state" => api::line_state().await,
        "line_set" => api::line_set(st(), arg(a, "url")?).await.map(Value::String),
        "line_mirrors" => api::line_mirrors().await,
        "line_probe" => {
            let urls: Vec<String> = arg(a, "urls")?;
            api::line_probe(urls.into_iter().take(80).collect()).await
        }
        "check_update" => api::check_update().await,
        "open_url" => Err("网页版由浏览器直接打开链接".into()),
        "set_orientation" => Ok(Value::Null),
        "api_login" => api::api_login(st(), arg(a, "username")?, arg(a, "password")?).await,
        "api_register" => {
            api::api_register(st(), arg(a, "username")?, arg(a, "password")?, arg(a, "email")?).await
        }
        "api_logout" => api::api_logout(st()).await,
        "api_me" => api::api_me(st()).await,
        "api_feed" => api::api_feed(st(), arg(a, "page")?, arg(a, "size")?).await,
        "api_category" => {
            api::api_category(st(), arg(a, "cate")?, arg(a, "page")?, arg(a, "size")?).await
        }
        "api_rank" => api::api_rank(st(), arg(a, "kind")?).await,
        "api_search" => api::api_search(st(), arg(a, "q")?, arg(a, "page")?, arg(a, "size")?).await,
        "cache_clear" => api::cache_clear().await.map(|_| Value::Null),
        "api_posts" => api::api_posts(st(), arg(a, "page")?, arg(a, "size")?).await,
        "api_post" => api::api_post(st(), arg(a, "id")?).await,
        "api_post_like" => api::api_post_like(st(), arg(a, "id")?, arg(a, "on")?).await,
        "api_post_collect" => api::api_post_collect(st(), arg(a, "id")?, arg(a, "on")?).await,
        "api_post_comments" => {
            api::api_post_comments(st(), arg(a, "id")?, arg(a, "page")?, arg(a, "size")?).await
        }
        "api_video" => api::api_video(st(), arg(a, "id")?).await,
        "api_play" => api::api_play(st(), arg(a, "id")?, arg(a, "ep")?).await,
        "api_comments" => {
            api::api_comments(st(), arg(a, "id")?, arg(a, "ep")?, arg(a, "page")?, arg(a, "size")?)
                .await
        }
        "api_comment_send" => {
            api::api_comment_send(
                st(),
                arg(a, "id")?,
                arg(a, "ep")?,
                arg(a, "text")?,
                arg(a, "reply_id")?,
            )
            .await
        }
        "api_like" => api::api_like(st(), arg(a, "id")?, arg(a, "ep")?, arg(a, "on")?).await,
        "api_collect" => api::api_collect(st(), arg(a, "id")?, arg(a, "on")?).await,
        "api_follow" => api::api_follow(st(), arg(a, "uid")?, arg(a, "on")?).await,
        "playback_log_status" => playback_log::playback_log_status().and_then(to_json),
        "playback_log_set" => playback_log::playback_log_set(arg(a, "enabled")?).and_then(to_json),
        "playback_log_write" => {
            playback_log::playback_log_write(arg(a, "entries")?).map(|_| Value::Null)
        }
        "playback_log_read" => playback_log::playback_log_read().map(Value::String),
        _ => Err(format!("未知命令：{cmd}")),
    }
}

async fn invoke(Path(cmd): Path<String>, body: Option<Json<Value>>) -> Response {
    let args = body.map(|Json(v)| v).unwrap_or(Value::Null);
    match dispatch(&cmd, &args).await {
        Ok(v) => (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")], Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, [(header::CACHE_CONTROL, "no-store")], Json(json!({"error": e})))
            .into_response(),
    }
}

/* ───────────────────────── 媒体代理（替代 hg:// 协议） ───────────────────────── */

/// 解析单段 Range（bytes=a-b / a- / -n），返回 [start, end]。
fn parse_range(raw: &str, len: usize) -> Option<(usize, usize)> {
    let spec = raw.trim().strip_prefix("bytes=")?;
    if spec.contains(',') || len == 0 {
        return None;
    }
    let (s, e) = spec.split_once('-')?;
    let (start, end) = if s.is_empty() {
        let n: usize = e.parse().ok()?;
        (len.saturating_sub(n), len - 1)
    } else {
        let start: usize = s.parse().ok()?;
        let end = if e.is_empty() { len - 1 } else { e.parse::<usize>().ok()?.min(len - 1) };
        (start, end)
    };
    (start <= end && start < len).then_some((start, end))
}

async fn media(
    AxState(st): AxState<Shared>,
    Path((mtok, kind)): Path<(String, String)>,
    method: Method,
    req: Request,
) -> Response {
    if !st.mtok_valid(&mtok) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let route = match kind.as_str() {
        "img" => "/img",
        "hls" => "/hls",
        "seg" => "/seg",
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let query = req.uri().query().unwrap_or("").to_string();
    let range = req.headers().get(header::RANGE).and_then(|v| v.to_str().ok()).map(str::to_string);
    let prefix = format!("/m/{mtok}");
    let resp = media::handle(route, &query, &prefix).await;

    // Safari 播放 mp4 必须支持 206 Range；hg:// 时代由 WebView 兜底，这里补上。
    let resp = match (resp.status().as_u16(), range.as_deref()) {
        (200, Some(r)) => {
            let len = resp.body().len();
            match parse_range(r, len) {
                Some((s, e)) => {
                    let (mut parts, body) = resp.into_parts();
                    parts.status = StatusCode::PARTIAL_CONTENT;
                    parts.headers.insert(
                        header::CONTENT_RANGE,
                        HeaderValue::from_str(&format!("bytes {s}-{e}/{len}")).unwrap(),
                    );
                    parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(e - s + 1));
                    tauri::http::Response::from_parts(parts, body[s..=e].to_vec())
                }
                None => {
                    let mut r = tauri::http::Response::new(Vec::new());
                    *r.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                    r.headers_mut().insert(
                        header::CONTENT_RANGE,
                        HeaderValue::from_str(&format!("bytes */{len}")).unwrap(),
                    );
                    r
                }
            }
        }
        _ => resp,
    };
    let mut out = resp.map(Body::from);
    if method == Method::HEAD {
        *out.body_mut() = Body::empty();
    }
    out
}

/* ───────────────────────── 启动 ───────────────────────── */

fn hash_password_from_stdin() {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).expect("read stdin");
    let pw = line.trim_end_matches(['\r', '\n']);
    if pw.len() < 8 {
        eprintln!("密码至少 8 位");
        std::process::exit(2);
    }
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).unwrap();
    let salt = SaltString::encode_b64(&salt).unwrap();
    let hash = Argon2::default().hash_password(pw.as_bytes(), &salt).unwrap();
    println!("{hash}");
}

#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("hash-password") {
        hash_password_from_stdin();
        return;
    }

    let cfg = Config {
        bind: env_or("HGHUB_BIND", "127.0.0.1:8901").parse().expect("HGHUB_BIND"),
        data: PathBuf::from(env_or("HGHUB_DATA", "/var/lib/hghub-web")),
        dist: PathBuf::from(env_or("HGHUB_DIST", "/opt/hghub-web/dist")),
        password_hash: std::env::var("HGHUB_PASSWORD_HASH").unwrap_or_default(),
        cookie_secure: env_or("HGHUB_COOKIE_SECURE", "1") != "0",
    };
    if PasswordHash::new(&cfg.password_hash).is_err() {
        eprintln!("HGHUB_PASSWORD_HASH 未设置或格式不对（用 `hghub-web hash-password` 生成）");
        std::process::exit(2);
    }
    std::fs::create_dir_all(&cfg.data).expect("create data dir");

    // 与 src-tauri/src/lib.rs 的 setup 一致：恢复线路 / 播放日志 / 上游会话
    tauri::set_app_data_dir(cfg.data.clone());
    net::bind_base(&cfg.data);
    playback_log::bind(&cfg.data);
    API.session.bind(cfg.data.clone());
    if !network_policy::strict_security() {
        // 历史落盘的宽松设置在网页版无效
        let _ = network_policy::set_strict_security(true);
    }

    let index_html = std::fs::read_to_string(cfg.dist.join("index.html")).expect("dist/index.html");
    let st: Shared = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
        fails: Mutex::new(HashMap::new()),
        index_html,
        cfg,
    });
    st.load_sessions();

    let assets = ServeDir::new(st.cfg.dist.clone()).append_index_html_on_directories(false);
    let app = Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/login", get(login_get).post(login_post))
        .route("/logout", post(logout).get(logout))
        .route("/api/invoke/{cmd}", post(invoke))
        .route("/m/{mtok}/{kind}", get(media).head(media))
        .fallback_service(assets)
        .layer(middleware::from_fn_with_state(st.clone(), require_session))
        .with_state(st.clone());

    let bind = st.cfg.bind;
    let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
    eprintln!(
        "hghub-web listening on http://{bind} (strict_security={}, base={})",
        network_policy::strict_security(),
        net::base()
    );
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("serve");
}
