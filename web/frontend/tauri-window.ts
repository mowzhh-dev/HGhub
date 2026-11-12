/**
 * 网页版的 `@tauri-apps/api/window` 替身：浏览器标签页没有原生窗口，
 * 最小化/最大化/拖拽缩放全部为空操作；全屏状态取自浏览器。
 */
const noop = async () => {};

const win = {
  isMaximized: async () => false,
  isFullscreen: async () => !!document.fullscreenElement,
  onResized: async (cb: () => void) => {
    window.addEventListener("resize", cb);
    return () => window.removeEventListener("resize", cb);
  },
  toggleMaximize: noop,
  minimize: noop,
  close: noop,
  startDragging: noop,
  startResizeDragging: noop,
};

export const getCurrentWindow = () => win;
