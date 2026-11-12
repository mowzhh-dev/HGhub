#!/bin/bash
# 在服务器上执行：安装/更新 hghub-web。用法：
#   sudo bash install.sh <hghub-web 二进制> <dist 目录>
# 首次安装需先写好 /etc/hghub-web/env（HGHUB_PASSWORD_HASH 用 `hghub-web hash-password` 生成）。
set -euo pipefail
BIN="$1"; DIST="$2"; HERE="$(cd "$(dirname "$0")" && pwd)"
id hghub >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hghub
install -d -m 755 /opt/hghub-web
install -m 755 "$BIN" /opt/hghub-web/hghub-web.new && mv /opt/hghub-web/hghub-web.new /opt/hghub-web/hghub-web
rm -rf /opt/hghub-web/dist.new && cp -r "$DIST" /opt/hghub-web/dist.new
rm -rf /opt/hghub-web/dist && mv /opt/hghub-web/dist.new /opt/hghub-web/dist
install -m 644 "$HERE/hghub-web.service" /etc/systemd/system/hghub-web.service
systemctl daemon-reload
systemctl enable hghub-web >/dev/null
systemctl restart hghub-web
sleep 1; systemctl --no-pager --lines=5 status hghub-web
