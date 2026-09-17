#!/usr/bin/env bash
# ============================================================
# 冒烟测试：一键验证项目是否健康（Windows git-bash 下执行）
#   用法: bash tests/smoke.sh
#   步骤: 1) 全部单元测试  2) 应用启动  3) 健康检查  4) 核心页面与功能
# ============================================================
set -u
cd "$(dirname "$0")/.."
PY=".venv/Scripts/python.exe"
PORT="${APP_PORT:-5000}"
TMPDIR_SMOKE=$(mktemp -d)

echo "============================================"
echo "  冒烟测试开始"
echo "============================================"

if [ ! -x "$PY" ]; then
    echo "[FAIL] 未找到虚拟环境 $PY —— 请先创建 .venv 并安装依赖"
    exit 1
fi

# 端口占用预检（避免多实例静默并存导致请求路由到旧进程）
if netstat -ano 2>/dev/null | grep "LISTENING" | grep -q ":$PORT "; then
    echo "[FAIL] 端口 $PORT 已被占用——请先停止旧服务实例再运行冒烟测试"
    exit 1
fi

# ---------- 1. 单元测试 ----------
echo ""
echo "[1/4] 运行全部单元测试..."
if ! "$PY" -m unittest discover -s tests; then
    echo "[FAIL] 单元测试未通过"
    exit 1
fi
echo "[OK] 单元测试全部通过"

# ---------- 2. 启动应用 ----------
echo ""
echo "[2/4] 启动应用（端口 $PORT）..."
"$PY" app.py &
APP_PID=$!
sleep 4

# ---------- 3. 健康检查 ----------
echo ""
echo "[3/4] 健康检查..."
HEALTH=$(curl -s --max-time 5 "http://127.0.0.1:$PORT/healthz" || true)
if echo "$HEALTH" | grep -q '"status":"ok"'; then
    echo "[OK] /healthz -> $HEALTH"
else
    echo "[FAIL] 健康检查失败（响应: $HEALTH）"
    kill $APP_PID 2>/dev/null
    exit 1
fi

# 登录页可达
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:$PORT/login")
if [ "$CODE" = "200" ]; then
    echo "[OK] /login -> 200"
else
    echo "[FAIL] /login 返回 $CODE"
    kill $APP_PID 2>/dev/null
    exit 1
fi

# 未登录拦截
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:$PORT/dashboard")
if [ "$CODE" = "302" ]; then
    echo "[OK] 未登录访问 /dashboard -> 302（正确拦截）"
else
    echo "[FAIL] 未登录访问 /dashboard 返回 $CODE（应为 302）"
    kill $APP_PID 2>/dev/null
    exit 1
fi

# 静态资源本地可用
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:$PORT/static/css/bootstrap.min.css")
if [ "$CODE" = "200" ]; then
    echo "[OK] 本地静态资源可用（断网演示保障）"
else
    echo "[FAIL] 静态资源返回 $CODE"
    kill $APP_PID 2>/dev/null
    exit 1
fi

# ---------- 4. 登录后核心页面可达（M1+M2 功能页） ----------
echo ""
echo "[4/4] 登录并验证核心页面..."
CK="$TMPDIR_SMOKE/cookies.txt"
curl -s -c "$CK" -d "username=admin&password=admin123" -o /dev/null \
    "http://127.0.0.1:$PORT/login"
for path in "/dashboard" "/logs" "/logs/sources" "/alerts" "/rules" "/ml" "/scanner" "/reports" "/settings"; do
    CODE=$(curl -s -b "$CK" -o /dev/null -w "%{http_code}" --max-time 5 \
        "http://127.0.0.1:$PORT$path")
    if [ "$CODE" = "200" ]; then
        echo "[OK] $path -> 200"
    else
        echo "[FAIL] $path 返回 $CODE"
        kill $APP_PID 2>/dev/null
        exit 1
    fi
done

# 规则测试工具：SQLi 日志应命中
RULE_ID=$(curl -s -b "$CK" "http://127.0.0.1:$PORT/rules" \
    | grep -oE 'value="[0-9]+"[^>]*>SQL 注入特征' | grep -oE '[0-9]+' | head -1)
if [ -n "$RULE_ID" ]; then
    RESULT=$(curl -s -b "$CK" --data-urlencode "rule_id=$RULE_ID" \
        --data-urlencode "sample_line=1.2.3.4 - - [01/Mar/2026:08:14:22 +0800] \"GET /p.php?id=1%27+UNION+SELECT+1-- HTTP/1.1\" 200 1 \"-\" \"ua\"" \
        "http://127.0.0.1:$PORT/rules/test")
    if echo "$RESULT" | grep -q "命中规则"; then
        echo "[OK] 规则测试工具：SQLi 日志命中"
    else
        echo "[FAIL] 规则测试工具未命中（规则引擎异常）"
        kill $APP_PID 2>/dev/null
        exit 1
    fi
fi

# ---------- 清理 ----------
kill $APP_PID 2>/dev/null
wait $APP_PID 2>/dev/null
rm -rf "$TMPDIR_SMOKE"

echo ""
echo "============================================"
echo "  冒烟测试通过 ✅"
echo "============================================"
