//! `#[tauri::command]` 的网页版替身：原样输出函数，不生成 IPC 包装。
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn command(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
