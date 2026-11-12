import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const host = process.env.TAURI_DEV_HOST;
// HG_WEB=1：构建网页版（iOS Safari 等浏览器用），Tauri API 换成 HTTP 适配层，产物输出到 web/dist
const web = process.env.HG_WEB === "1";
const shim = (f: string) => fileURLToPath(new URL(`./web/frontend/${f}`, import.meta.url));
const { version } = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf8"),
) as { version: string };

export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  // 版本号只维护 package.json（CI 会按 tag 改写它），界面里的版本由这里注入，避免写死后漂移
  define: {
    __APP_VERSION__: JSON.stringify(version),
    __HG_WEB__: JSON.stringify(web),
  },
  resolve: web
    ? {
        alias: {
          "@tauri-apps/api/core": shim("tauri-core.ts"),
          "@tauri-apps/api/window": shim("tauri-window.ts"),
        },
      }
    : undefined,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  build: {
    outDir: web ? "web/dist" : "dist",
    emptyOutDir: true,
    target: "es2021",
    minify: "esbuild",
    sourcemap: false,
  },
});
