//! `tauri_plugin_opener` 替身：服务端没有“系统默认浏览器”，外链由前端 window.open 处理。
pub struct Opener;

impl Opener {
    pub fn open_url(&self, _url: &str, _with: Option<&str>) -> Result<(), String> {
        Err("网页版由浏览器直接打开链接".to_string())
    }
}

pub trait OpenerExt {
    fn opener(&self) -> Opener {
        Opener
    }
}

impl OpenerExt for tauri_shim::AppHandle {}
