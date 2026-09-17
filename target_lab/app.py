# -*- coding: utf-8 -*-
"""本地测试靶场：一个**故意包含漏洞**的教学站点（扫描器的验证目标）

【用途】供主动扫描器（M4/M5）验证漏洞检出能力。
    仅在本地运行（127.0.0.1:5050），不对外暴露——合规零风险。

【预置漏洞清单】（与《验收测试方案.md》TC-SCAN-03 对应）
    vuln-sqli-1      /product.php?id=   SQL 注入（报错型 + 真值/假值差异）
    vuln-sqli-2      /news.php?id=      SQL 注入（同上）
    vuln-sqli-3      /user.php?id=      SQL 注入（模拟 MySQL：报错/联合/布尔/时间盲注）
    vuln-sqli-4      /vip.php?id=       SQL 注入（模拟 MySQL + 朴素关键词过滤 → 需绕过变体）
    vuln-xss-1       /search?q=         反射型 XSS（未转义回显）
    vuln-xss-2       /vip-search?q=     反射型 XSS + 朴素黑名单过滤（需绕过变体）
    vuln-traversal-1 /download?file=    目录遍历（模拟 Linux 服务器）
    敏感文件          /.env /backup.zip 敏感文件泄露
    后台暴露          /admin             可直接访问的后台入口
    组件过期          jQuery 1.12.4      前端库版本低于修复版本（CVE 匹配）
    安全头            首页               部分缺失 + 部分配置不当（ALLOWALL / 宽松 CSP）

【非漏洞页面】（供目录探测/信息收集，属正常业务）
    /                首页（含 Flask 指纹特征）
    /robots.txt      含 Disallow 线索
    /admin           后台入口（可访问 —— 本身就是配置缺陷，扫描器应发现）
    /safe-search?q=  与 /search 功能相同但**正确转义** —— 误报控制对照页
    /api/users       正常接口

【运行】
    .venv\\Scripts\\python.exe target_lab/app.py
"""
import re
import sqlite3
import time
from html import escape
from urllib.parse import unquote

from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["SERVER_NAME_PORT"] = 5050

# ---------------------------------------------------------------- 假数据库

USERS = [
    (1, "zhangsan", "产品经理", "zhang@example.com"),
    (2, "lisi", "开发工程师", "li@example.com"),
    (3, "wangwu", "测试工程师", "wang@example.com"),
]
PRODUCTS = [
    (1, "机械键盘", 399),
    (2, "显示器", 1299),
    (3, "人体工学椅", 899),
]
NEWS = [
    (1, "公司获得新融资", "我们很高兴地宣布……"),
    (2, "新产品发布", "新一代产品即将上线……"),
]


def _memory_db():
    """每个请求新建内存库（避免并发问题，数据固定）"""
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT, email TEXT)")
    con.execute("CREATE TABLE products (id INTEGER, name TEXT, price INTEGER)")
    con.execute("CREATE TABLE news (id INTEGER, title TEXT, content TEXT)")
    con.executemany("INSERT INTO users VALUES (?,?,?,?)", USERS)
    con.executemany("INSERT INTO products VALUES (?,?,?)", PRODUCTS)
    con.executemany("INSERT INTO news VALUES (?,?,?)", NEWS)
    return con


# 首页安全响应头（演示两类问题，供安全头检测器验证）：
#   - X-Frame-Options: ALLOWALL   → 配置不当（该值不被现代浏览器支持）
#   - CSP: default-src * unsafe-inline → 配置不当（等于没设）
#   - X-Content-Type-Options: nosniff  → 正确配置（对照）
#   另有 HSTS / Referrer-Policy 完全缺失
DEMO_SECURITY_HEADERS = {
    "X-Frame-Options": "ALLOWALL",
    "Content-Security-Policy": "default-src * 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
}


# ================================================================ 正常页面

@app.route("/")
def index():
    """首页（含框架与前端库指纹特征、安全响应头演示，供信息收集与检测）"""
    return (
        "<html><head><title>示例商城</title>"
        '<meta name="generator" content="Flask - 内部商城系统 v2.1">'
        # 教学说明：老版本前端库是中小企业站点最常见的过期组件（CVE 匹配的验证目标）
        '<script src="/static/js/jquery-1.12.4.min.js"></script>'
        "</head><body>"
        "<h1>欢迎访问示例商城</h1>"
        '<p>商品查询：<a href="/product.php?id=1">/product.php?id=1</a></p>'
        '<p>公司新闻：<a href="/news.php?id=1">/news.php?id=1</a></p>'
        '<p>会员中心：<a href="/user.php?id=1">/user.php?id=1</a></p>'
        '<p>VIP 专区：<a href="/vip.php?id=1">/vip.php?id=1</a></p>'
        '<p>资料下载：<a href="/download?file=readme.txt">/download?file=readme.txt</a></p>'
        '<p>VIP 搜索：<a href="/vip-search?q=test">/vip-search?q=test</a></p>'
        '<p>安全搜索（对照页）：<a href="/safe-search?q=test">/safe-search?q=test</a></p>'
        '<form action="/search" method="get">搜索：<input name="q"><button>查询</button></form>'
        "</body></html>"
    ), 200, DEMO_SECURITY_HEADERS


@app.route("/static/js/jquery-1.12.4.min.js")
def jquery_js():
    """占位脚本（仅用于版本指纹演示，不实现真实功能）"""
    return "/* jQuery 1.12.4 (教学靶场占位) */", 200, {"Content-Type": "application/javascript"}


@app.route("/robots.txt")
def robots():
    """robots 暴露目录线索（扫描器的目录探测会使用）"""
    return (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /backup.zip\n"
        "Disallow: /.env\n"
    ), 200, {"Content-Type": "text/plain"}


@app.route("/admin")
def admin():
    """后台入口可直接访问（配置缺陷，扫描器应能发现）"""
    return "<html><body><h2>管理后台</h2><p>请先登录（本页面未做访问控制——属配置缺陷）</p></body></html>"


# ================================================================ 漏洞：SQL 注入 ×2

def _vulnerable_product_query(pid: str) -> str:
    """【故意不安全】字符串拼接 SQL —— vuln-sqli-1"""
    con = _memory_db()
    # ⚠️ 教学靶场故意使用拼接（真实项目必须参数化查询）
    sql = f"SELECT id, name, price FROM products WHERE id = {pid}"
    rows = con.execute(sql).fetchall()
    return sql, rows


@app.route("/product.php")
def product():
    pid = request.args.get("id", "1")
    try:
        sql, rows = _vulnerable_product_query(pid)
    except sqlite3.Error as exc:
        # 报错信息泄露（SQL 注入的可检出特征）
        return f"<h3>查询出错</h3><pre>sqlite3.OperationalError: {exc}</pre>", 500
    if not rows:
        return "<h3>未找到该商品</h3>", 200
    items = "".join(f"<li>{r[1]} - ￥{r[2]}</li>" for r in rows)
    return f"<h3>商品详情</h3><ul>{items}</ul>"


@app.route("/news.php")
def news():
    """【故意不安全】字符串拼接 SQL —— vuln-sqli-2"""
    nid = request.args.get("id", "1")
    con = _memory_db()
    try:
        rows = con.execute(f"SELECT id, title, content FROM news WHERE id = {nid}").fetchall()
    except sqlite3.Error as exc:
        return f"<h3>查询出错</h3><pre>sqlite3.OperationalError: {exc}</pre>", 500
    if not rows:
        return "<h3>暂无此新闻</h3>", 200
    return "".join(f"<h3>{r[1]}</h3><p>{r[2]}</p>" for r in rows)


# ================================================================ 模拟 MySQL 后端
# 教学说明：真实中小企业站点多为 PHP + MySQL（$sql = "SELECT ... WHERE id = $id"）。
# 靶场不引入数据库依赖，用"模拟 MySQL"按真实引擎的行为特征给出等价响应，
# 使四种注入技术（报错/联合/布尔/时间盲注）都能被真实验证。

MYSQL_SYNTAX_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near '{frag}' at line 1")

VIPS = [
    (1, "gold_vip", "13800000001"),
    (2, "silver_vip", "13800000002"),
]

# 朴素黑名单（真实世界里最常见的"错误防护"写法：按短语匹配 + 在一次解码后检查）
BLOCK_LIST = ("'", '"', "\\", "--", "union select", "sleep(", "and 1=1",
              "or 1=1", "<script")


def _naive_filter(value: str) -> bool:
    """朴素关键词过滤（故意实现得很弱，用于演示绕过）"""
    low = (value or "").lower()
    return any(word in low for word in BLOCK_LIST)


def _vip_page(rows) -> str:
    if not rows:
        return "<html><body><h3>会员查询</h3><p>未找到该会员。</p></body></html>"
    items = "".join(f"<li>{r[0]} - {r[1]} - {r[2]}</li>" for r in rows)
    return f"<html><body><h3>会员查询</h3><ul>{items}</ul></body></html>"


def _mysql_error(frag: str):
    """MySQL 风格报错页（含函数名与语法错误文本——报错型注入的可检出特征）"""
    detail = MYSQL_SYNTAX_ERROR.format(frag=(frag or "")[:60])
    return (f"<b>Warning</b>: mysqli_fetch_array() expects parameter 1 to be "
            f"mysqli_result, bool given in /var/www/vip.php on line 18<br>"
            f"<pre>{detail}</pre>"), 500


def _mysql_run(uid: str):
    """按 MySQL 拼接语义"执行"参数（教学模拟）。

    与真实 MySQL 一致的行为：
      - 注释等价空白   /* ... */ 被引擎忽略（注释分隔绕过黑名单的原理）
      - SLEEP(n)       真实阻塞 n 秒（时间盲注可检出）
      - UNION SELECT   追加注入的常量行（联合查询可检出）
      - AND 1=1 / 1=2  恒真 / 恒假条件（布尔盲注可检出）
      - 语法残缺       返回 MySQL 风格报错（报错型注入可检出）
    """
    sql = re.sub(r"/\*.*?\*/", " ", uid or "")          # 注释 → 空白

    m = re.search(r"\bsleep\s*\(\s*([\d.]+)\s*\)", sql, re.IGNORECASE)
    if m:
        time.sleep(min(float(m.group(1)), 5))           # 真实延迟（上限 5s 防跑飞）
        return _vip_page(VIPS[:1]), 200

    m = re.search(r"\bunion\b\s+select\b(.*)$", sql, re.IGNORECASE | re.DOTALL)
    if m:
        consts = re.findall(r"\d+", m.group(1))[:3]     # 注入的常量行
        rows = VIPS + [(int(c), "injected_row", "-") for c in consts]
        return _vip_page(rows), 200

    m = re.search(r"\band\b\s+(\d+)\s*=\s*(\d+)", sql, re.IGNORECASE)
    if m:
        if m.group(1) != m.group(2):                    # 恒假条件 → 无结果
            return _vip_page([]), 200
        sql = sql[:m.start()] + sql[m.end():]           # 恒真条件 → 去掉后继续

    if "'" in sql or '"' in sql or "\\" in sql:
        return _mysql_error(sql)
    m = re.fullmatch(r"\s*(\d+)\s*", sql)
    if not m:
        return _mysql_error(sql)
    return _vip_page([r for r in VIPS if r[0] == int(m.group(1))]), 200


@app.route("/user.php")
def user():
    """【故意不安全】模拟 MySQL 会员查询 —— vuln-sqli-3（无过滤）

    四种注入技术均可在此页复现：
      /user.php?id=1'                      → 报错型（MySQL 语法错误回显）
      /user.php?id=1 UNION SELECT 1,2,3     → 联合查询（注入行被渲染）
      /user.php?id=1 AND 1=1 / 1=2          → 布尔盲注（结果集不同）
      /user.php?id=1 AND SLEEP(3)           → 时间盲注（响应真实延迟 3 秒）
    """
    uid = request.args.get("id", "1")
    html, code = _mysql_run(uid)
    return html, code


@app.route("/vip.php")
def vip():
    """【故意不安全】模拟 MySQL + 朴素关键词过滤 —— vuln-sqli-4（需绕过变体）

    教学说明：很多真实站点用"黑名单关键词"代替参数化查询，且检查时机错误，
    导致过滤可被绕过。本页可复现两类真实的绕过：
      - 双重编码  1%2527：过滤器在"解码一次后"检查，看不见引号；
                  应用随后又解码一次，SQL 收到的仍是 1' → 注入成功
      - 注释分隔  1/**/UNION/**/SELECT：黑名单按短语 "union select" 匹配，
                  注释插入后短语不存在 → 绕过成功
    普通 payload（1'、1 UNION SELECT …）会被拦下——扫描器必须使用
    对抗性变体才能检出本页漏洞（《验收测试方案.md》TC-SCAN-08）。
    """
    value = request.args.get("id", "1")        # Flask 解码一次：1%2527 → 1%27
    if _naive_filter(value):
        return ("<html><body><h3>请求被拦截</h3>"
                "<p>检测到可疑字符，本次请求已被安全策略拦截。</p></body></html>"), 200
    decoded_again = unquote(value)             # ⚠️ 应用又解码一次（二次解码缺陷）
    html, code = _mysql_run(decoded_again)
    return html, code


# ================================================================ 漏洞：反射型 XSS

@app.route("/search")
def search():
    """【故意不安全】q 参数未转义直接回显 —— vuln-xss-1"""
    q = request.args.get("q", "")
    # ⚠️ 教学靶场故意不转义（真实项目必须使用模板自动转义）
    return (
        f"<html><body><h3>搜索结果</h3>"
        f"<p>您搜索的是：{q}</p>"
        f"<p>未找到相关商品。</p></body></html>"
    )


# 朴素黑名单（大小写敏感 —— 真实世界最常见的错误写法：照着样例原文写死关键词）
XSS_BLOCK_LIST = ("<script", "</script", "onerror=", "onload=", "onmouseover=",
                  "onclick=", "javascript:")


def _xss_blocked(value: str) -> bool:
    """朴素过滤：命中黑名单则拦截（大小写敏感，故 <ScRiPt> 可绕过）"""
    return any(word in (value or "") for word in XSS_BLOCK_LIST)


@app.route("/vip-search")
def vip_search():
    """【故意不安全】反射型 XSS + 朴素关键词过滤 —— vuln-xss-2（需绕过变体）

    教学说明：很多真实站点用"黑名单关键词"代替输出编码，且按样例原文写死
    （大小写敏感）——这是真实世界最常见的错误写法。本页可复现两类绕过：
      - 大小写混写  <ScRiPt>alert(1)</ScRiPt>：黑名单只认小写 <script → 绕过成功
      - 双重编码    %253Cscript%253E：过滤时看不见标签 → 应用二次解码后还原 → 绕过成功
    明文的 <script> / onerror= / javascript: 会被拦下——扫描器必须使用
    对抗性变体才能检出本页漏洞（《验收测试方案.md》TC-SCAN-08）。
    """
    q = request.args.get("q", "")
    if _xss_blocked(q):
        return ("<html><body><h3>搜索结果</h3>"
                "<p>检测到可疑脚本内容，本次搜索已被安全策略拦截。</p></body></html>"), 200
    value = unquote(q)                       # ⚠️ 应用又解码一次（二次解码缺陷）
    return (f"<html><body><h3>VIP 搜索</h3><p>您搜索的是：{value}</p></body></html>")


@app.route("/safe-search")
def safe_search():
    """【正确写法对照页】与 /search 功能相同，但输出经 HTML 转义

    教学说明：这是安全编码的正确示范。扫描器在此页**不应**报出 XSS——
    它是"检出率 100% + 误报 0"双指标中的误报控制项（负样本）。
    """
    q = request.args.get("q", "")
    return (
        f"<html><body><h3>安全搜索结果</h3>"
        f"<p>您搜索的是：{escape(q)}</p>"
        f"<p>未找到相关商品。</p></body></html>"
    )


# ================================================================ 漏洞：目录遍历（模拟）

@app.route("/download")
def download():
    """【故意不安全】file 参数拼接路径 —— vuln-traversal-1

    教学说明：真实服务器上此处可读取任意系统文件。
    靶场为演示安全（不真读文件系统），对包含遍历特征的请求返回
    **模拟的系统文件内容**（含检测器可识别的特征串）。
    """
    filename = request.args.get("file", "readme.txt")

    traversal_marks = ("../", "..\\", "..%2f", "..%5c", "%2e%2e")
    if any(mark in filename.lower() for mark in traversal_marks):
        # 模拟 Linux 服务器被读取 /etc/passwd 的情形
        fake_passwd = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        )
        return fake_passwd, 200, {"Content-Type": "text/plain"}

    return "readme: 本目录提供公开资料下载。", 200, {"Content-Type": "text/plain"}


# ================================================================ 漏洞：敏感文件泄露

@app.route("/.env")
def env_file():
    """【故意暴露】环境配置文件（含假凭据）—— 敏感文件泄露"""
    return (
        "APP_ENV=production\n"
        "DB_HOST=127.0.0.1\n"
        "DB_NAME=shop\n"
        "DB_USER=shop_app\n"
        "DB_PASSWORD=Fake_Password_123!\n"
        "SECRET_KEY=fake-secret-key-for-lab\n"
    ), 200, {"Content-Type": "text/plain"}


@app.route("/backup.zip")
def backup_zip():
    """【故意暴露】备份文件（返回 ZIP 文件头特征）—— 敏感文件泄露"""
    payload = b"PK\x03\x04" + b"\x00" * 60      # ZIP 魔数 + 占位
    return payload, 200, {"Content-Type": "application/zip",
                          "Content-Disposition": "attachment; filename=backup.zip"}


@app.route("/api/users")
def api_users():
    """正常 API（供信息收集/爬虫用）"""
    return jsonify([{"id": u[0], "username": u[1], "role": u[2]} for u in USERS])


# ================================================================ 入口

if __name__ == "__main__":
    print("=" * 56)
    print("  本地测试靶场（故意含漏洞，仅限本机使用）")
    print("  地址: http://127.0.0.1:5050")
    print("  漏洞: SQLi×4 / XSS×1 / 目录遍历×1 / 敏感文件×2 / 安全头缺失")
    print("  对照: /safe-search（已转义，扫描器不应报 XSS）")
    print("=" * 56)
    app.run(host="127.0.0.1", port=5050, threaded=True, debug=False)
