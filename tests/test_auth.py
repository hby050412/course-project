# -*- coding: utf-8 -*-
"""M1-4 认证模块单元测试

覆盖：
- LoginGuard 纯逻辑（锁定/解锁/清零，时钟注入免等待）
- Flask 路由集成（未登录拦截/登录成功失败/锁定/登出）——对应 TC-AUTH-01~06
"""
import tempfile
import unittest
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.blueprints.auth import guard
from secplat.utils.login_guard import LoginGuard


class TestLoginGuard(unittest.TestCase):
    """锁定逻辑（时钟注入，无需真实等待）"""

    def setUp(self):
        self.g = LoginGuard(max_fails=5, lock_seconds=300)

    def test_not_locked_initially(self):
        allowed, remaining = self.g.check("admin")
        self.assertTrue(allowed)
        self.assertEqual(remaining, 0)

    def test_lock_triggers_at_max_fails(self):
        for i in range(4):
            locked, _ = self.g.record_failure("admin", now=1000 + i)
            self.assertFalse(locked, f"第 {i+1} 次不应锁定")
        locked, sec = self.g.record_failure("admin", now=1004)  # 第 5 次
        self.assertTrue(locked)
        self.assertEqual(sec, 300)

    def test_locked_rejects_even_correct_credentials(self):
        for i in range(5):
            self.g.record_failure("admin", now=1000 + i)
        allowed, remaining = self.g.check("admin", now=1010)
        self.assertFalse(allowed)
        self.assertGreater(remaining, 0)

    def test_unlock_after_lock_expires(self):
        for i in range(5):
            self.g.record_failure("admin", now=1000 + i)
        # 锁定到期（1004+300=1304 之后）
        allowed, remaining = self.g.check("admin", now=1305)
        self.assertTrue(allowed)
        self.assertEqual(remaining, 0)
        # 解锁后计数已重置
        self.assertEqual(self.g.fails("admin"), 0)

    def test_success_resets_counter(self):
        self.g.record_failure("admin", now=1000)
        self.g.record_failure("admin", now=1001)
        self.assertEqual(self.g.fails("admin"), 2)
        self.g.record_success("admin")
        self.assertEqual(self.g.fails("admin"), 0)

    def test_users_are_independent(self):
        for i in range(5):
            self.g.record_failure("admin", now=1000 + i)
        allowed, _ = self.g.check("other_user", now=1010)
        self.assertTrue(allowed, "锁定不应影响其他用户名")

    def test_failure_during_lock_does_not_extend(self):
        for i in range(5):
            self.g.record_failure("admin", now=1000 + i)
        # 锁定期内再次失败：返回剩余时间，不重置锁定
        locked, sec = self.g.record_failure("admin", now=1100)
        self.assertTrue(locked)
        self.assertLessEqual(sec, 300)


class TestAuthRoutes(unittest.TestCase):
    """Flask 集成（临时数据库，种子含 admin/admin123）"""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()

        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + (
                Path(cls.tmpdir.name) / "test_auth.db").as_posix()
            TESTING = True

        cls.app = create_app(TestConfig)
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        # Windows 下需先释放 SQLite 文件句柄，否则临时目录无法删除
        from secplat.models import db
        with cls.app.app_context():
            db.session.remove()
            db.engine.dispose()
        cls.tmpdir.cleanup()

    def setUp(self):
        guard.reset()   # 每用例独立，避免锁定状态串扰

    # ------------------------------ TC-AUTH-01~02

    def test_login_page_accessible(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("安全检测平台", resp.get_data(as_text=True))

    def test_business_pages_require_login(self):
        for path in ("/", "/dashboard"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 302, path)
            self.assertIn("/login", resp.headers["Location"], path)

    # ------------------------------ TC-AUTH-03

    def test_login_success_redirects_dashboard(self):
        resp = self.client.post("/login",
                                data={"username": "admin", "password": "admin123"},
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/dashboard", resp.headers["Location"])
        with self.client.session_transaction() as sess:
            self.assertEqual(sess["username"], "admin")
        # 登录后可访问仪表盘
        page = self.client.get("/dashboard")
        self.assertEqual(page.status_code, 200)

    def test_login_success_then_next_redirect(self):
        resp = self.client.post("/login?next=/logs",
                                data={"username": "admin", "password": "admin123"})
        self.assertIn("/logs", resp.headers["Location"])

    # ------------------------------ TC-AUTH-04

    def test_login_wrong_password(self):
        resp = self.client.post("/login",
                                data={"username": "admin", "password": "wrong"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("用户名或密码错误", resp.get_data(as_text=True))

    def test_login_unknown_user(self):
        resp = self.client.post("/login",
                                data={"username": "nobody", "password": "x"})
        self.assertEqual(resp.status_code, 401)

    # ------------------------------ TC-AUTH-05（锁定）

    def test_lockout_after_five_failures(self):
        for i in range(5):
            self.client.post("/login", data={"username": "admin", "password": "wrong"})
        # 第 6 次尝试（即使密码正确）也应被拒绝
        resp = self.client.post("/login",
                                data={"username": "admin", "password": "admin123"})
        self.assertEqual(resp.status_code, 429)
        self.assertIn("锁定", resp.get_data(as_text=True))

    # ------------------------------ TC-AUTH-06（登出）

    def test_logout_clears_session(self):
        self.client.post("/login", data={"username": "admin", "password": "admin123"})
        resp = self.client.get("/logout")
        self.assertEqual(resp.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
        # 登出后业务页再次拦截
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    # ------------------------------ TC-AUTH-07（密码哈希）

    def test_password_stored_hashed(self):
        with self.app.app_context():
            from secplat.models import User
            user = User.query.filter_by(username="admin").first()
            self.assertNotIn("admin123", user.password_hash)
            self.assertGreater(len(user.password_hash), 40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
