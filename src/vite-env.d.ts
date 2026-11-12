/// <reference types="vite/client" />

/** 由 vite.config.ts 的 define 注入，来源是 package.json 的 version */
declare const __APP_VERSION__: string;

/** 网页版构建（HG_WEB=1）时为 true：invoke 走 HTTP、媒体走 /m/ 代理 */
declare const __HG_WEB__: boolean;
