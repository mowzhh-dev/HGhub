//! 网页版服务端用的最小 `tauri` 替身。
//!
//! 目的：让 `src-tauri/src/*.rs`（api / net / media / 解密等核心模块）不改一行就能在
//! 独立 HTTP 服务里编译复用。只提供这些模块实际用到的符号：
//! `tauri::command`、`tauri::http`、`tauri::State`、`tauri::AppHandle`、`tauri::Manager`。
pub use http;
pub use tauri_shim_macros::command;

use std::path::PathBuf;
use std::sync::OnceLock;

/// 与 tauri::State 同形：对托管状态的共享引用。
pub struct State<'r, T: Send + Sync + 'static>(&'r T);

impl<'r, T: Send + Sync + 'static> State<'r, T> {
    pub fn new(inner: &'r T) -> Self {
        Self(inner)
    }
}

impl<T: Send + Sync + 'static> std::ops::Deref for State<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0
    }
}

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// 设定数据目录（相当于 Tauri 的 app_data_dir），启动时调用一次。
pub fn set_app_data_dir(dir: PathBuf) {
    let _ = DATA_DIR.set(dir);
}

#[derive(Clone, Copy, Default)]
pub struct AppHandle;

pub struct PathResolver;

impl PathResolver {
    pub fn app_data_dir(&self) -> Result<PathBuf, String> {
        DATA_DIR.get().cloned().ok_or_else(|| "data dir not set".to_string())
    }
}

pub trait Manager {
    fn path(&self) -> PathResolver;
}

impl Manager for AppHandle {
    fn path(&self) -> PathResolver {
        PathResolver
    }
}
