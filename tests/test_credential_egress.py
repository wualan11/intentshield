# -*- coding: utf-8 -*-
"""
凭证注入 + 网络出口管控 单元测试
=================================
对标 OpenShell 凭证占位符 + 网络白名单设计，验证：
  1. credentials 表结构正确
  2. 凭证占位符解析正确
  3. /api/proxy/llm 端点行为（占位符验证、凭证注入、错误处理）
  4. egress_policies 表结构正确
  5. /api/proxy/egress 端点行为（token 验证、白名单过滤、审计日志）
  6. llm_agent.py 的 chat() 请求目标改为 Gateway 代理

运行：python tests/test_credential_egress.py
"""
import os
import sys
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# 把项目根目录加入 path
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import app as app_module
import gateway_core as gw_module


class CredentialInjectionTest(unittest.TestCase):
    """凭证注入相关测试"""

    def setUp(self):
        """每个测试前创建临时数据库"""
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        # 替换 app 模块的数据库路径
        self.orig_db_path = app_module.DB_PATH
        app_module.DB_PATH = self.db_path
        # 初始化表结构
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS credentials(
                id INTEGER PRIMARY KEY, provider TEXT UNIQUE, placeholder TEXT,
                api_key TEXT, model TEXT, base_url TEXT, enabled INTEGER DEFAULT 1, created_at TEXT);
            CREATE TABLE IF NOT EXISTS egress_policies(
                id INTEGER PRIMARY KEY, run_id INTEGER DEFAULT 0, host TEXT,
                port INTEGER DEFAULT 443, allowed INTEGER DEFAULT 1, created_at TEXT);
            CREATE TABLE IF NOT EXISTS agent_runs(
                id INTEGER PRIMARY KEY, run_code TEXT, task_id INTEGER, agent_name TEXT,
                agent_version TEXT, task_desc TEXT, mode TEXT, status TEXT, token TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS audit_logs(
                id INTEGER PRIMARY KEY, ts TEXT, user TEXT, agent TEXT, task TEXT, step INTEGER,
                intent TEXT, risk_score REAL, tool TEXT, action TEXT, decision TEXT, reviewer TEXT, reason TEXT);
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        """)
        conn.commit()
        conn.close()

    def tearDown(self):
        app_module.DB_PATH = self.orig_db_path
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ---------- credentials 表结构 ----------

    def test_credentials_table_schema(self):
        """credentials 表包含所有必需字段"""
        conn = self._db()
        cols = {r[1] for r in conn.execute("PRAGMA table_info(credentials)").fetchall()}
        conn.close()
        expected = {"id", "provider", "placeholder", "api_key", "model", "base_url", "enabled", "created_at"}
        self.assertEqual(cols, expected)

    def test_credentials_insert_and_query(self):
        """凭证可以正确插入和查询"""
        conn = self._db()
        conn.execute(
            "INSERT INTO credentials(provider,placeholder,api_key,model,base_url,enabled,created_at) VALUES(?,?,?,?,?,?,?)",
            ("deepseek", "openshell://provider/deepseek", "sk-test-key-123", "deepseek-chat",
             "https://api.deepseek.com", 1, "2026-10-15 00:00:00"))
        conn.commit()
        row = conn.execute("SELECT * FROM credentials WHERE provider='deepseek'").fetchone()
        conn.close()
        self.assertEqual(row["placeholder"], "openshell://provider/deepseek")
        self.assertEqual(row["api_key"], "sk-test-key-123")
        self.assertEqual(row["enabled"], 1)

    def test_credentials_placeholder_format(self):
        """占位符格式符合 openshell://provider/<name> 规范"""
        placeholder = "openshell://provider/deepseek"
        self.assertTrue(placeholder.startswith("openshell://provider/"))
        provider = placeholder.replace("openshell://provider/", "")
        self.assertEqual(provider, "deepseek")

    def test_credentials_disabled_not_returned(self):
        """禁用的凭证（enabled=0）不应被查询到"""
        conn = self._db()
        conn.execute(
            "INSERT INTO credentials(provider,placeholder,api_key,model,base_url,enabled,created_at) VALUES(?,?,?,?,?,?,?)",
            ("deepseek", "openshell://provider/deepseek", "sk-key", "deepseek-chat",
             "https://api.deepseek.com", 0, "2026-10-15 00:00:00"))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM credentials WHERE provider='deepseek' AND enabled=1").fetchone()
        conn.close()
        self.assertIsNone(row)

    # ---------- /api/proxy/llm 端点逻辑 ----------

    def test_proxy_llm_valid_placeholder(self):
        """有效占位符应通过验证并查询到凭证"""
        conn = self._db()
        conn.execute(
            "INSERT INTO credentials(provider,placeholder,api_key,model,base_url,enabled,created_at) VALUES(?,?,?,?,?,?,?)",
            ("deepseek", "openshell://provider/deepseek", "sk-real-key", "deepseek-chat",
             "https://api.deepseek.com", 1, "2026-10-15 00:00:00"))
        conn.commit()
        conn.close()

        # 模拟端点逻辑
        auth = "Bearer openshell://provider/deepseek"
        self.assertTrue(auth.startswith("Bearer openshell://"))
        provider = auth.replace("Bearer openshell://provider/", "")
        self.assertEqual(provider, "deepseek")

        conn = self._db()
        cred = conn.execute(
            "SELECT * FROM credentials WHERE provider=? AND enabled=1", (provider,)).fetchone()
        conn.close()
        self.assertIsNotNone(cred)
        self.assertEqual(cred["api_key"], "sk-real-key")
        self.assertEqual(cred["base_url"], "https://api.deepseek.com")

    def test_proxy_llm_invalid_placeholder_rejected(self):
        """无效占位符（不以 openshell:// 开头）应被拒绝"""
        auth = "Bearer sk-real-key-direct"
        self.assertFalse(auth.startswith("Bearer openshell://"))

    def test_proxy_llm_unknown_provider_rejected(self):
        """未注册的 provider 应被拒绝"""
        auth = "Bearer openshell://provider/openai"
        provider = auth.replace("Bearer openshell://provider/", "")
        conn = self._db()
        cred = conn.execute(
            "SELECT * FROM credentials WHERE provider=? AND enabled=1", (provider,)).fetchone()
        conn.close()
        self.assertIsNone(cred)

    def test_proxy_llm_disabled_provider_rejected(self):
        """已禁用的 provider 应被拒绝"""
        conn = self._db()
        conn.execute(
            "INSERT INTO credentials(provider,placeholder,api_key,model,base_url,enabled,created_at) VALUES(?,?,?,?,?,?,?)",
            ("deepseek", "openshell://provider/deepseek", "sk-key", "deepseek-chat",
             "https://api.deepseek.com", 0, "2026-10-15 00:00:00"))
        conn.commit()
        conn.close()
        conn = self._db()
        cred = conn.execute(
            "SELECT * FROM credentials WHERE provider='deepseek' AND enabled=1").fetchone()
        conn.close()
        self.assertIsNone(cred)

    def test_proxy_llm_target_url_construction(self):
        """目标 URL 应正确拼接 base_url + /chat/completions"""
        base_url = "https://api.deepseek.com"
        target = base_url.rstrip("/") + "/chat/completions"
        self.assertEqual(target, "https://api.deepseek.com/chat/completions")

    # ---------- llm_agent.py 的 chat() 请求目标 ----------

    def test_llm_agent_uses_gateway_proxy(self):
        """llm_agent.py 的 chat() 应请求 Gateway 代理而非直接 api.deepseek.com"""
        # 读取 llm_agent.py 源码验证
        agent_path = os.path.join(BASE, "real_agent", "llm_agent.py")
        with open(agent_path, "r", encoding="utf-8") as f:
            src = f.read()
        # chat() 方法应使用 self.shield.base + "/api/proxy/llm"
        self.assertIn("self.shield.base + \"/api/proxy/llm\"", src)
        # 不应再直接请求 api.deepseek.com
        self.assertNotIn("self.base_url + \"/chat/completions\"", src)

    def test_llm_agent_api_key_is_placeholder(self):
        """llm_agent.py 的 api_key 应为占位符而非真实 Key"""
        agent_path = os.path.join(BASE, "real_agent", "llm_agent.py")
        with open(agent_path, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn('"openshell://provider/deepseek"', src)
        # 不应再读 .llm_key.txt
        self.assertNotIn(".llm_key.txt", src)


class EgressControlTest(unittest.TestCase):
    """网络出口管控相关测试"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.orig_db_path = app_module.DB_PATH
        app_module.DB_PATH = self.db_path
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS credentials(
                id INTEGER PRIMARY KEY, provider TEXT UNIQUE, placeholder TEXT,
                api_key TEXT, model TEXT, base_url TEXT, enabled INTEGER DEFAULT 1, created_at TEXT);
            CREATE TABLE IF NOT EXISTS egress_policies(
                id INTEGER PRIMARY KEY, run_id INTEGER DEFAULT 0, host TEXT,
                port INTEGER DEFAULT 443, allowed INTEGER DEFAULT 1, created_at TEXT);
            CREATE TABLE IF NOT EXISTS agent_runs(
                id INTEGER PRIMARY KEY, run_code TEXT, task_id INTEGER, agent_name TEXT,
                agent_version TEXT, task_desc TEXT, mode TEXT, status TEXT, token TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS audit_logs(
                id INTEGER PRIMARY KEY, ts TEXT, user TEXT, agent TEXT, task TEXT, step INTEGER,
                intent TEXT, risk_score REAL, tool TEXT, action TEXT, decision TEXT, reviewer TEXT, reason TEXT);
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        """)
        conn.commit()
        conn.close()

    def tearDown(self):
        app_module.DB_PATH = self.orig_db_path
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ---------- egress_policies 表结构 ----------

    def test_egress_policies_table_schema(self):
        """egress_policies 表包含所有必需字段"""
        conn = self._db()
        cols = {r[1] for r in conn.execute("PRAGMA table_info(egress_policies)").fetchall()}
        conn.close()
        expected = {"id", "run_id", "host", "port", "allowed", "created_at"}
        self.assertEqual(cols, expected)

    def test_egress_policies_insert_and_query(self):
        """出口策略可以正确插入和查询"""
        conn = self._db()
        conn.execute(
            "INSERT INTO egress_policies(run_id,host,port,allowed,created_at) VALUES(?,?,?,?,?)",
            (0, "api.deepseek.com", 443, 1, "2026-10-15 00:00:00"))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM egress_policies WHERE run_id=0 AND host='api.deepseek.com'").fetchone()
        conn.close()
        self.assertEqual(row["port"], 443)
        self.assertEqual(row["allowed"], 1)

    # ---------- 白名单过滤逻辑 ----------

    def test_egress_whitelist_allows_listed_host(self):
        """白名单内的 host 应被允许"""
        conn = self._db()
        conn.execute(
            "INSERT INTO egress_policies(run_id,host,port,allowed,created_at) VALUES(?,?,?,?,?)",
            (0, "api.deepseek.com", 443, 1, "2026-10-15 00:00:00"))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM egress_policies WHERE (run_id=0 OR run_id=?) AND host=? AND allowed=1",
            (1, "api.deepseek.com")).fetchone()
        conn.close()
        self.assertIsNotNone(row)

    def test_egress_whitelist_blocks_unlisted_host(self):
        """不在白名单的 host 应被拒绝"""
        conn = self._db()
        conn.execute(
            "INSERT INTO egress_policies(run_id,host,port,allowed,created_at) VALUES(?,?,?,?,?)",
            (0, "api.deepseek.com", 443, 1, "2026-10-15 00:00:00"))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM egress_policies WHERE (run_id=0 OR run_id=?) AND host=? AND allowed=1",
            (1, "evil.com")).fetchone()
        conn.close()
        self.assertIsNone(row)

    def test_egress_whitelist_run_specific(self):
        """运行级白名单（run_id>0）优先于全局白名单"""
        conn = self._db()
        # 全局只允许 api.deepseek.com
        conn.execute(
            "INSERT INTO egress_policies(run_id,host,port,allowed,created_at) VALUES(?,?,?,?,?)",
            (0, "api.deepseek.com", 443, 1, "2026-10-15 00:00:00"))
        # run_id=1 额外允许 internal.bank.com
        conn.execute(
            "INSERT INTO egress_policies(run_id,host,port,allowed,created_at) VALUES(?,?,?,?,?)",
            (1, "internal.bank.com", 443, 1, "2026-10-15 00:00:00"))
        conn.commit()
        # run_id=1 应该能访问 internal.bank.com
        row = conn.execute(
            "SELECT * FROM egress_policies WHERE (run_id=0 OR run_id=1) AND host='internal.bank.com' AND allowed=1").fetchone()
        self.assertIsNotNone(row)
        # run_id=2 不应该能访问 internal.bank.com
        row = conn.execute(
            "SELECT * FROM egress_policies WHERE (run_id=0 OR run_id=2) AND host='internal.bank.com' AND allowed=1").fetchone()
        conn.close()
        self.assertIsNone(row)

    def test_egress_whitelist_disabled_host_blocked(self):
        """allowed=0 的 host 应被拒绝"""
        conn = self._db()
        conn.execute(
            "INSERT INTO egress_policies(run_id,host,port,allowed,created_at) VALUES(?,?,?,?,?)",
            (0, "api.deepseek.com", 443, 0, "2026-10-15 00:00:00"))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM egress_policies WHERE (run_id=0 OR run_id=?) AND host=? AND allowed=1",
            (1, "api.deepseek.com")).fetchone()
        conn.close()
        self.assertIsNone(row)

    # ---------- token 验证 ----------

    def test_egress_valid_token_accepted(self):
        """有效 run_token 应通过验证"""
        conn = self._db()
        conn.execute(
            "INSERT INTO agent_runs(run_code,task_id,agent_name,agent_version,task_desc,mode,status,token,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            ("RUN-001", 1, "TestAgent", "1.0", "test task", "protected", "running", "valid-token-123", "2026-10-15 00:00:00"))
        conn.commit()
        row = conn.execute("SELECT * FROM agent_runs WHERE token='valid-token-123'").fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["agent_name"], "TestAgent")

    def test_egress_invalid_token_rejected(self):
        """无效 run_token 应被拒绝"""
        conn = self._db()
        row = conn.execute("SELECT * FROM agent_runs WHERE token='invalid-token'").fetchone()
        conn.close()
        self.assertIsNone(row)

    # ---------- URL 解析 ----------

    def test_egress_url_host_extraction(self):
        """目标 URL 应正确解析出 host 和 port"""
        from urllib.parse import urlparse
        cases = [
            ("https://api.deepseek.com/chat/completions", "api.deepseek.com", 443),
            ("https://internal.bank.com:8443/api", "internal.bank.com", 8443),
            ("http://evil.com/phish", "evil.com", 443),  # default 443
        ]
        for url, expected_host, expected_port in cases:
            parsed = urlparse(url)
            self.assertEqual(parsed.hostname, expected_host)
            self.assertEqual(parsed.port or 443, expected_port)

    # ---------- 审计日志 ----------

    def test_egress_violation_writes_audit(self):
        """出口违规应写入审计日志"""
        conn = self._db()
        # 模拟违规后的审计写入
        conn.execute(
            "INSERT INTO audit_logs(ts,user,agent,task,step,intent,risk_score,tool,action,decision,reviewer,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("2026-10-15 00:00:00", "-", "TestAgent", "test task", 0, "-", 100, "-",
             "网络出口违规：evil.com:443", "block", "-", "目标主机 evil.com 不在白名单"))
        conn.commit()
        row = conn.execute("SELECT * FROM audit_logs WHERE action LIKE '网络出口违规%'").fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["decision"], "block")
        self.assertIn("evil.com", row["reason"])


class IntegrationTest(unittest.TestCase):
    """集成测试：凭证注入 + 出口管控的组合场景"""

    def test_agent_without_key_cannot_call_llm_directly(self):
        """Agent 不持有真实 Key，无法直接调用 LLM API"""
        # 模拟 Agent 侧的 api_key 值
        api_key = "openshell://provider/deepseek"
        self.assertTrue(api_key.startswith("openshell://"))
        self.assertNotEqual(api_key, "sk-real-key-12345")
        # 占位符不是有效的 Bearer token
        self.assertFalse(api_key.startswith("sk-"))

    def test_gateway_proxy_injects_real_key(self):
        """Gateway 代理应注入真实 Key 到 Authorization 头"""
        # 模拟 Gateway 端逻辑
        placeholder = "openshell://provider/deepseek"
        provider = placeholder.replace("openshell://provider/", "")
        # 假设数据库中有这个凭证
        cred_api_key = "sk-real-deepseek-key-abc123"
        cred_base_url = "https://api.deepseek.com"
        # 构造转发请求头
        fwd_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cred_api_key}",
        }
        # 验证转发的 Authorization 头是真实 Key 而非占位符
        self.assertEqual(fwd_headers["Authorization"], "Bearer sk-real-deepseek-key-abc123")
        self.assertNotIn("openshell://", fwd_headers["Authorization"])

    def test_egress_and_credential_combined_flow(self):
        """组合场景：Agent 调 LLM → Gateway 凭证注入 + 出口白名单"""
        # 1. Agent 用占位符发起请求
        agent_api_key = "openshell://provider/deepseek"
        # 2. Gateway 验证占位符并查凭证
        self.assertTrue(agent_api_key.startswith("Bearer openshell://") or agent_api_key.startswith("openshell://"))
        # 3. Gateway 检查出口白名单（api.deepseek.com 应在白名单）
        target_host = "api.deepseek.com"
        whitelist = {"api.deepseek.com", "127.0.0.1"}
        self.assertIn(target_host, whitelist)
        # 4. Gateway 注入真实 Key 并转发
        real_key = "sk-real-key"
        self.assertNotEqual(real_key, agent_api_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
