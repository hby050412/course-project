# -*- coding: utf-8 -*-
"""认证蓝图：登录 / 登出 / 登录保护装饰器

安全设计（对应《毕设项目方案.md》6.5 节）：
- 密码 werkzeug 哈希校验（数据库不存明文）
- session 有效期 8 小时（create_app 中设置 permanent_session_lifetime）
- 连续 5 次失败锁定 5 分钟（LoginGuard，含剩余时间提示）
"""
import functools

from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash

from config import Config
from ..models import User
from ..utils.login_guard import LoginGuard

auth_bp = Blueprint("auth", __name__)

# 全局登录保护（本地单管理员场景；真实产品应结合 IP 维度）
guard = LoginGuard(max_fails=Config.LOGIN_MAX_FAILS,
                   lock_seconds=Config.LOGIN_LOCK_MINUTES * 60)


def login_required(view):
    """未登录访问业务页面 → 跳转登录页（携带 next 便于登录后返回）"""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("请输入用户名和密码", "warning")
            return render_template("login.html"), 400

        allowed, remaining = guard.check(username)
        if not allowed:
            flash(f"该账号已被锁定，请在 {remaining} 秒后重试", "danger")
            return render_template("login.html"), 429

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            guard.record_success(username)
            session.permanent = True          # 启用 8 小时有效期
            session.clear()                   # 防会话固定
            session["user_id"] = user.id
            session["username"] = user.username
            next_url = request.args.get("next") or request.form.get("next")
            return redirect(next_url if next_url and next_url.startswith("/")
                            else url_for("dashboard.show"))

        locked, lock_sec = guard.record_failure(username)
        if locked:
            flash(f"连续失败次数过多，账号已锁定 {lock_sec} 秒", "danger")
            return render_template("login.html"), 429
        left = Config.LOGIN_MAX_FAILS - guard.fails(username)
        flash(f"用户名或密码错误，还可尝试 {left} 次", "danger")
        return render_template("login.html"), 401

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("已安全退出", "info")
    return redirect(url_for("auth.login"))
