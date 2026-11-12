#!/usr/bin/env python3
"""HGhub 网页版验收：python3 verify.py <base-url>  （访问密码从 stdin 读入，不进命令行）

逐项检查（任一项不过即非 0 退出）：
  1. 未登录：首页 302→/login，接口 401，媒体代理 401，静态资源被挡
  2. 错误密码被拒
  3. 正确密码登录，首页注入媒体令牌
  4. 首页 feed 是真实数据
  5. 任选一部剧：详情可打开、HLS 清单经代理 200、key/分片经代理 200、封面 200 且是图片
"""
import http.cookiejar, json, random, re, ssl, sys, urllib.error, urllib.parse, urllib.request

BASE = sys.argv[1].rstrip("/")
PW = sys.stdin.readline().rstrip("\r\n")
ctx = ssl.create_default_context()
results = []


def check(name, ok, detail=""):
    ok = bool(ok)
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  — {detail}" if detail else ""))
    return ok


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def opener(jar=None, follow=False):
    hs = [urllib.request.HTTPSHandler(context=ctx)]
    if jar is not None:
        hs.append(urllib.request.HTTPCookieProcessor(jar))
    if not follow:
        hs.append(NoRedirect())
    return urllib.request.build_opener(*hs)


def req(op, method, path, data=None, headers=None):
    url = path if path.startswith("http") else BASE + path
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with op.open(r, timeout=40) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


anon = opener()
# ---------- 1. 未登录 ----------
s, h, _ = req(anon, "GET", "/")
check("未登录访问首页 → 跳登录页", s in (302, 303, 307) and (h.get("Location") or "").endswith("/login"), f"{s} {h.get('Location')}")
s, _, b = req(anon, "GET", "/login")
check("登录页可打开且不暴露应用内容", s == 200 and b"password" in b and b"HGhub" not in b, f"{s}")
s, _, _ = req(anon, "POST", "/api/invoke/api_feed", json.dumps({"page": 1, "size": 5}).encode(), {"Content-Type": "application/json"})
check("未登录调接口 → 401", s == 401, f"{s}")
s, _, _ = req(anon, "GET", "/m/" + "0" * 32 + "/img?u=https%3A%2F%2Fexample.com%2Fa.jpg")
check("未登录走媒体代理 → 401", s == 401, f"{s}")
s, h, _ = req(anon, "GET", "/apple-touch-icon.png")
check("未登录拿静态资源 → 被挡", s in (302, 303, 307, 401), f"{s}")

# ---------- 2. 错误密码 ----------
s, h, _ = req(anon, "POST", "/login", b"password=wrong-password-123", {"Content-Type": "application/x-www-form-urlencoded"})
check("错误密码被拒", s == 401 and "Set-Cookie" not in h, f"{s}")

# ---------- 3. 正确密码 ----------
class LoopbackPolicy(http.cookiejar.DefaultCookiePolicy):
    """服务器本机直连 http://127.0.0.1 验证时，Secure Cookie 也照样回传。"""

    def return_ok_secure(self, cookie, request):
        return True if urllib.parse.urlparse(BASE).hostname == "127.0.0.1" else super().return_ok_secure(cookie, request)


jar = http.cookiejar.CookieJar(policy=LoopbackPolicy())
me = opener(jar)
s, h, _ = req(me, "POST", "/login", ("password=" + urllib.parse.quote(PW)).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
cookie = h.get("Set-Cookie") or ""
check("正确密码登录", s in (302, 303) and "hg_sess=" in cookie and "HttpOnly" in cookie, f"{s} cookie-flags={';'.join(p.strip() for p in cookie.split(';')[1:])}")
s, _, b = req(me, "GET", "/")
m = re.search(rb'__HG_LOCAL__="(/m/[0-9a-f]{32})"', b)
check("登录后首页加载并注入媒体令牌", s == 200 and m is not None and b'id="root"' in b, f"{s}")
if not m:
    sys.exit(1)
LOCAL = m.group(1).decode()


def invoke(cmd, **args):
    s, _, b = req(me, "POST", f"/api/invoke/{cmd}", json.dumps(args).encode(), {"Content-Type": "application/json"})
    return s, json.loads(b or b"null")


# ---------- 4. feed ----------
s, feed = invoke("api_feed", page=1, size=20)
items = (feed or {}).get("items") or [] if s == 200 else []
real = [i for i in items if isinstance(i.get("id"), int) and i.get("title") and i.get("cover")]
check("首页 feed 是真实数据", s == 200 and len(real) >= 5, f"HTTP {s}, {len(items)} 条，例：{[i['title'] for i in real[:3]]}")
if not real:
    sys.exit(1)

# ---------- 5. 任选一部剧 ----------
pick = random.choice(real[:10])
s, detail = invoke("api_video", id=pick["id"])
eps = (detail or {}).get("episodes") or []
check("详情可打开", s == 200 and detail.get("id") == pick["id"] and detail.get("title"), f"#{pick['id']} 《{detail.get('title') if s == 200 else detail}》 {len(eps)} 集")
ep = (eps[0].get("ep_num") if eps else 1) or 1
s, play = invoke("api_play", id=pick["id"], ep=ep)
vurl = (play or {}).get("video_url", "") if s == 200 else ""
check("播放地址可取", bool(vurl), f"HTTP {s}, ep {ep}, {'m3u8' if '.m3u8' in vurl else vurl[:30]}")

s, h, b = req(me, "GET", f"{LOCAL}/hls?u=" + urllib.parse.quote(vurl, safe=""))
text = b.decode("utf-8", "replace")
check("HLS 清单经代理 200", s == 200 and text.startswith("#EXTM3U"), f"{s} {h.get('Content-Type')} {len(b)}B")


def first_media_line(t):
    return next((l.strip() for l in t.splitlines() if l.strip() and not l.startswith("#")), None)


# 主清单 → 子清单（如有）
line = first_media_line(text)
if line and "#EXT-X-STREAM-INF" in text:
    s, h, b = req(me, "GET", line)
    text = b.decode("utf-8", "replace")
    check("子清单经代理 200", s == 200 and text.startswith("#EXTM3U"), f"{s} {len(b)}B")
    line = first_media_line(text)
leaks = [l for l in text.splitlines() if l and not l.startswith("#") and not l.startswith(LOCAL + "/")]
check("清单内分片地址全部改写到代理", not leaks, f"未改写 {len(leaks)} 行")
key = re.search(r'#EXT-X-KEY:[^\n]*URI="([^"]+)"', text)
if key:
    s, _, kb = req(me, "GET", key.group(1))
    check("加密 key 经代理 200", s == 200 and len(kb) == 16, f"{s} {len(kb)}B")
s, h, sb = req(me, "GET", line)
check("视频分片经代理 200", s == 200 and len(sb) > 1000, f"{s} {h.get('Content-Type')} {len(sb)}B")
s, h, sb2 = req(me, "GET", line, headers={"Range": "bytes=0-1023"})
check("分片支持 Range(206)", s == 206 and len(sb2) == 1024, f"{s} {h.get('Content-Range')}")

cover = detail.get("cover") or pick["cover"]
s, h, cb = req(me, "GET", f"{LOCAL}/img?u=" + urllib.parse.quote(cover, safe=""))
ctype = h.get("Content-Type") or ""
magic = cb[:4]
is_img = ctype.startswith("image/") and (magic[:3] == b"\xff\xd8\xff" or magic == b"\x89PNG" or cb[8:12] == b"WEBP" or magic[:3] == b"GIF")
check("封面经代理解密 200 且是图片", s == 200 and is_img, f"{s} {ctype} {len(cb)}B")

# 登出后令牌失效
req(me, "POST", "/logout")
s, _, _ = req(anon, "GET", f"{LOCAL}/img?u=" + urllib.parse.quote(cover, safe=""))
check("登出后媒体令牌立即失效", s == 401, f"{s}")

print(f"\n{sum(results)}/{len(results)} 项通过")
sys.exit(0 if all(results) else 1)
