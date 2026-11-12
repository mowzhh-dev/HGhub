/**
 * 网页版的 `@tauri-apps/api/core` 替身（vite.config.ts 在 HG_WEB=1 时把导入别名到这里）。
 * 原来 invoke(cmd, args) 走 Tauri IPC 调 Rust；网页版改走 POST /api/invoke/<cmd>，
 * 服务端（web/server）用同一套 Rust 代码处理。错误语义与 Tauri 一致：reject 一个字符串。
 */

/** Tauri 会把 JS 侧 camelCase 参数名转成 Rust 的 snake_case，这里保持同样约定。 */
const snake = (k: string) => k.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

export async function invoke<T = unknown>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  // 原生插件命令（如安卓 app|exit）在浏览器里没有意义
  if (cmd.startsWith("plugin:")) return undefined as T;
  if (cmd === "open_url") {
    const url = String(args?.url ?? "");
    if (/^https?:\/\//i.test(url)) window.open(url, "_blank", "noopener,noreferrer");
    return undefined as T;
  }
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args ?? {})) body[snake(k)] = v;

  let resp: Response;
  try {
    resp = await fetch(`/api/invoke/${encodeURIComponent(cmd)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw "网络连接失败，请检查网络";
  }
  if (resp.status === 401) {
    location.href = "/login";
    throw "登录已失效";
  }
  const data = await resp.json().catch(() => null);
  if (!resp.ok) {
    throw data && typeof data.error === "string" ? data.error : `HTTP ${resp.status}`;
  }
  return data as T;
}

export type PluginListener = { unregister: () => Promise<void> };

/** 浏览器没有原生插件事件（安卓返回键等），返回一个空监听。 */
export async function addPluginListener(
  _plugin: string,
  _event: string,
  _cb: (payload: unknown) => void,
): Promise<PluginListener> {
  return { unregister: async () => {} };
}
