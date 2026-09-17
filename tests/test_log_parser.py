# -*- coding: utf-8 -*-
"""M1-1 日志解析器单元测试

覆盖：
- 三种格式正常样例（字段级断言）
- 畸形样例（空行/乱行/字段缺失）返回 None
- parse_file 行级容错（坏行跳过不中断）
- 时间解析：SSH 补年份 / 非法时间兜底
"""
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from secplat.engine.log_parser import parse_line, parse_file


class TestSSHParser(unittest.TestCase):
    """① SSH（syslog 风格）"""

    def test_failed_invalid_user(self):
        line = ("Mar  1 08:14:22 server sshd[1234]: Failed password for invalid user "
                "admin from 192.168.1.50 port 50231 ssh2")
        ev = parse_line(line, "ssh")
        self.assertIsNotNone(ev)
        self.assertEqual(ev.log_type, "ssh")
        self.assertEqual(ev.src_ip, "192.168.1.50")
        self.assertEqual(ev.src_port, 50231)
        self.assertEqual(ev.dst_port, 22)
        self.assertEqual(ev.username, "admin")
        self.assertEqual(ev.detail["event"], "failed")
        self.assertEqual(ev.raw, line)

    def test_failed_valid_user(self):
        line = ("Mar  1 08:20:00 server sshd[1236]: Failed password for root "
                "from 10.0.0.99 port 40001 ssh2")
        ev = parse_line(line, "ssh")
        self.assertEqual(ev.username, "root")
        self.assertEqual(ev.detail["event"], "failed")
        self.assertNotIn("reason", ev.detail)

    def test_accepted(self):
        line = ("Mar  1 08:15:01 server sshd[1235]: Accepted password for zhangsan "
                "from 10.0.0.8 port 52100 ssh2")
        ev = parse_line(line, "ssh")
        self.assertEqual(ev.username, "zhangsan")
        self.assertEqual(ev.detail["event"], "success")
        self.assertEqual(ev.src_ip, "10.0.0.8")

    def test_invalid_user_line(self):
        line = ("Mar  1 08:16:00 server sshd[1237]: Invalid user test from "
                "172.16.0.5 port 33221")
        ev = parse_line(line, "ssh")
        self.assertEqual(ev.username, "test")
        self.assertEqual(ev.detail["event"], "failed")
        self.assertEqual(ev.detail["reason"], "invalid_user")

    def test_ts_year_filled(self):
        """SSH 时间无年份 → 应为当前年份"""
        line = ("Mar  1 08:14:22 server sshd[1]: Failed password for admin "
                "from 1.2.3.4 port 100 ssh2")
        ev = parse_line(line, "ssh")
        self.assertTrue(ev.ts.startswith(str(datetime.now().year)))
        self.assertEqual(ev.ts, f"{datetime.now().year}-03-01T08:14:22")

    def test_malformed(self):
        for bad in ["", "   ", "这是一行乱码", "sshd: something else",
                    "Mar  1 08:14:22 server sshd[1]: Failed password for"]:
            self.assertIsNone(parse_line(bad, "ssh"), f"应返回 None: {bad!r}")


class TestWebParser(unittest.TestCase):
    """② Web（Apache combined 风格）"""

    def test_get_with_injection_url(self):
        line = ('192.168.1.50 - - [01/Mar/2026:08:14:22 +0800] '
                '"GET /index.php?id=1%27+OR+%271%27%3D%271 HTTP/1.1" 200 1234 '
                '"http://example.com/" "Mozilla/5.0 (Windows NT 10.0)"')
        ev = parse_line(line, "web")
        self.assertIsNotNone(ev)
        self.assertEqual(ev.log_type, "web")
        self.assertEqual(ev.src_ip, "192.168.1.50")
        self.assertEqual(ev.ts, "2026-03-01T08:14:22")
        self.assertEqual(ev.method, "GET")
        self.assertEqual(ev.url, "/index.php?id=1%27+OR+%271%27%3D%271")
        self.assertEqual(ev.status_code, 200)
        self.assertEqual(ev.user_agent, "Mozilla/5.0 (Windows NT 10.0)")
        self.assertEqual(ev.detail["referer"], "http://example.com/")

    def test_post(self):
        line = ('10.0.0.8 - - [15/Mar/2026:23:10:05 +0800] '
                '"POST /login HTTP/1.1" 302 512 "-" "curl/8.0"')
        ev = parse_line(line, "web")
        self.assertEqual(ev.method, "POST")
        self.assertEqual(ev.url, "/login")
        self.assertEqual(ev.status_code, 302)
        self.assertEqual(ev.user_agent, "curl/8.0")

    def test_404(self):
        line = ('172.16.0.9 - - [01/Mar/2026:09:00:00 +0800] '
                '"GET /admin HTTP/1.1" 404 0 "-" "sqlmap/1.7"')
        ev = parse_line(line, "web")
        self.assertEqual(ev.status_code, 404)
        self.assertEqual(ev.user_agent, "sqlmap/1.7")

    def test_malformed(self):
        for bad in ["", "192.168.1.50 - - 未闭合的格式",
                    '192.168.1.50 - - [01/Mar/2026:08:14:22 +0800] "GET /x HTTP/1.1"',
                    '1.1.1.1 - - [] "" 200 1 "" ""']:
            self.assertIsNone(parse_line(bad, "web"), f"应返回 None: {bad!r}")


class TestNmapParser(unittest.TestCase):
    """③ Nmap（自定义 CSV）"""

    def test_normal(self):
        line = "2026-03-01T08:14:22,192.168.1.50,192.168.1.100,22,tcp,open"
        ev = parse_line(line, "scan")
        self.assertIsNotNone(ev)
        self.assertEqual(ev.log_type, "scan")
        self.assertEqual(ev.ts, "2026-03-01T08:14:22")
        self.assertEqual(ev.src_ip, "192.168.1.50")
        self.assertEqual(ev.dst_ip, "192.168.1.100")
        self.assertEqual(ev.dst_port, 22)
        self.assertEqual(ev.proto, "tcp")
        self.assertEqual(ev.detail["state"], "open")

    def test_closed_state(self):
        line = "2026-03-01T08:14:23,192.168.1.50,192.168.1.100,3306,tcp,closed"
        ev = parse_line(line, "scan")
        self.assertEqual(ev.dst_port, 3306)
        self.assertEqual(ev.detail["state"], "closed")

    def test_malformed(self):
        for bad in ["", "2026-03-01T08:14:22,1.1.1.1,2.2.2.2",  # 字段不足
                    "时间,1.1.1.1,2.2.2.2,22,tcp,open",          # 时间非法
                    "192.168.1.50,192.168.1.100,22,tcp,open"]:   # 缺时间
            self.assertIsNone(parse_line(bad, "scan"), f"应返回 None: {bad!r}")


class TestAliasesAndErrors(unittest.TestCase):
    """别名与错误处理"""

    def test_source_type_aliases(self):
        ssh_line = ("Mar  1 08:14:22 server sshd[1]: Failed password for admin "
                    "from 1.2.3.4 port 100 ssh2")
        self.assertIsNotNone(parse_line(ssh_line, "SSHD"))    # 大小写不敏感
        self.assertIsNotNone(parse_line(ssh_line, " ssh "))   # 空白容忍

        web_line = ('1.1.1.1 - - [01/Mar/2026:00:00:00 +0800] "GET / HTTP/1.1" 200 1 "-" "ua"')
        self.assertIsNotNone(parse_line(web_line, "apache"))
        self.assertIsNotNone(parse_line(web_line, "nginx"))

        nmap_line = "2026-03-01T00:00:00,1.1.1.1,2.2.2.2,80,tcp,open"
        self.assertIsNotNone(parse_line(nmap_line, "nmap"))

    def test_unknown_source_type(self):
        self.assertIsNone(parse_line("any line", "unknown_type"))
        self.assertIsNone(parse_line("any line", None))

    def test_bad_ts_fallback(self):
        """时间字段异常 → 兜底当前时间（不抛异常）"""
        line = ('1.1.1.1 - - [不是时间] "GET / HTTP/1.1" 200 1 "-" "ua"')
        ev = parse_line(line, "web")
        self.assertIsNotNone(ev)
        self.assertTrue(ev.ts.startswith(str(datetime.now().year)))


class TestParseFile(unittest.TestCase):
    """parse_file 行级容错"""

    def test_mixed_good_and_bad_lines(self):
        good1 = ("Mar  1 08:14:22 server sshd[1]: Failed password for admin "
                 "from 1.2.3.4 port 100 ssh2")
        good2 = "2026-03-01T08:14:22,192.168.1.50,192.168.1.100,22,tcp,open"
        content = f"{good1}\n\n乱码行\n{good2}\n只有半行,1.1.1.1\n"

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "sample.log"
            f.write_text(content, encoding="utf-8")
            events = list(parse_file(f, "ssh"))  # 注意：混合格式时坏行按 None 跳过
        # ssh 解析下 good2 也解析不了（格式不符）→ 只有 good1 通过
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].username, "admin")

    def test_same_format_file(self):
        lines = [
            '1.1.1.1 - - [01/Mar/2026:00:00:01 +0800] "GET /a HTTP/1.1" 200 1 "-" "ua1"',
            '2.2.2.2 - - [01/Mar/2026:00:00:02 +0800] "GET /b HTTP/1.1" 404 1 "-" "ua2"',
            '坏行',
            '3.3.3.3 - - [01/Mar/2026:00:00:03 +0800] "POST /c HTTP/1.1" 500 1 "-" "ua3"',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "web.log"
            f.write_text("\n".join(lines), encoding="utf-8")
            events = list(parse_file(f, "web"))
        self.assertEqual(len(events), 3)
        self.assertEqual([e.status_code for e in events], [200, 404, 500])


if __name__ == "__main__":
    unittest.main(verbosity=2)
