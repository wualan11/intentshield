# -*- coding: utf-8 -*-
"""
gateway_core.py — 智链盾 Action Gateway 核心
================================================
独立于任何 Agent 的运行时安全执行点：
外部 Agent 在调用工具【之前】必须把【客观信号】发到 Gateway，
五因子风险分由【平台侧】根据原始任务、历史意图、工具与参数计算——
Agent 不能自报安全分数。

决策：allow（Agent 才允许真实执行工具）/ confirm（挂起，等待平台人工核准）
      / block（Agent 收到拒绝，工具绝不执行）
"""
import re, os, json, time, uuid, sys, sqlite3
from datetime import datetime
# gateway_core 仅由平台进程(app.py)导入：直接复用主模块，避免双份加载
app = sys.modules.get("app") or sys.modules["__main__"]

# 网关心跳：最近一次 Agent 过闸调用的时间戳（用于仪表盘展示监督者在线状态）
LAST_CALL_TS = None

# ------------------------------------------------------------------
# 真实运行表
# ------------------------------------------------------------------
GW_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_runs(
    id INTEGER PRIMARY KEY, run_code TEXT, task_id INTEGER,
    agent_name TEXT, agent_version TEXT, task_desc TEXT,
    mode TEXT, status TEXT, token TEXT,
    allowed_count INTEGER DEFAULT 0, monitor_count INTEGER DEFAULT 0,
    confirmed_count INTEGER DEFAULT 0, blocked_count INTEGER DEFAULT 0,
    leak_occurred INTEGER DEFAULT 0,
    created_at TEXT, finished_at TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS gateway_calls(
    id INTEGER PRIMARY KEY, run_id INTEGER, step INTEGER, request_id TEXT,
    tool TEXT, args_json TEXT, purpose TEXT, intent_cat TEXT,
    factors_json TEXT, score REAL, level TEXT, decision TEXT,
    status TEXT, reviewer TEXT, reason TEXT,
    executed INTEGER DEFAULT 0, result_digest TEXT, error TEXT,
    latency_ms REAL, created_at TEXT, resolved_at TEXT, reasons TEXT);
"""

# 兼容升级：为对话式运行时时间线新增字段（已有库幂等迁移）
GW_MIGRATE = """
ALTER TABLE intent_traces ADD COLUMN reasoning TEXT;
ALTER TABLE intent_traces ADD COLUMN tool_result TEXT;
ALTER TABLE gateway_calls ADD COLUMN analysis_json TEXT;
ALTER TABLE gateway_calls ADD COLUMN reasons TEXT;
"""

# Agent 注册码（模拟「Agent 接入需注册审批」；实际部署可换签发流程）
AGENT_REG_CODE = "intentshield-agent-2026"

# ------------------------------------------------------------------
# 工具客观风险画像（与平台工具注册中心一致）
# perm_level: L0 公开 / L1 内部 / L2 敏感 / L3 高影响
# ------------------------------------------------------------------
TOOL_PROFILE = {
    "read_file":      {"risk": 10, "perm": "L1", "data": "内部"},
    "list_dir":       {"risk": 5,  "perm": "L0", "data": "公开"},
    "fs_read":        {"risk": 15, "perm": "L1", "data": "内部"},
    "fs_list":        {"risk": 5,  "perm": "L0", "data": "公开"},
    "write_file":     {"risk": 25, "perm": "L1", "data": "内部"},
    "query_db":       {"risk": 45, "perm": "L2", "data": "敏感"},
    "export_data":    {"risk": 70, "perm": "L2", "data": "敏感"},
    "send_email":     {"risk": 60, "perm": "L2", "data": "内部"},
    "submit_workflow":{"risk": 80, "perm": "L3", "data": "高影响"},
}
SENSITIVE_TABLES = ["customer", "credit", "transaction", "account", "loan", "id_card", "征信", "客户"]
# 个人敏感信息（PII）字段词：export_data 导出字段中出现即视为敏感外泄动作
PII_EXPORT_WORDS = ["phone", "mobile", "手机", "id_card", "身份证", "email", "邮箱"]
WRITE_SQL = re.compile(r"\b(delete|drop|update|insert|truncate|alter)\b", re.I)
INTERNAL_EMAIL_SUFFIX = ("@bank.internal", "@company.cn", "@intentshield.local")

# ------------------------------------------------------------------
# 文件路径级授权校验（越权访问检测）
# 本任务授权范围为 public/；restricted/ 属高权限目录，
# 工具本身不做权限判断——由平台在执行前识别并阻断。
# ------------------------------------------------------------------
FS_RESTRICTED_DIR = "restricted"

def _fs_path_norm(p):
    """归一化 fs_read/fs_list 的 path 参数：统一分隔符、去开头 ./ 与前导斜杠"""
    return str(p or "").strip().replace("\\", "/").lstrip("./").lstrip("/")

def _fs_restricted_hit(tool, args):
    """判定 fs_read/fs_list 是否试图访问高权限目录 restricted/"""
    if tool not in ("fs_read", "fs_list"):
        return False
    p = _fs_path_norm((args or {}).get("path", ""))
    return p == FS_RESTRICTED_DIR or p.startswith(FS_RESTRICTED_DIR + "/") \
        or (FS_RESTRICTED_DIR + "/") in p

# ------------------------------------------------------------------
# 执行前 SQL 静态校验（平台侧数据库防火墙能力，独立于 Agent）
# 用 EXPLAIN 让 SQLite 只做语义解析/计划生成而不真正访问/修改数据，
# 从而在工具执行【之前】识别：多语句注入、不存在的表/字段、非法导出。
# ------------------------------------------------------------------
_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "real_agent", "workspace", "bank.db")
_schema_cache = {"mtime": 0, "schema": None}

def _load_schema():
    """以只读方式读取沙箱库的表结构（不读取任何业务数据）。"""
    try:
        mtime = os.path.getmtime(_DB_PATH)
    except OSError:
        return None
    if _schema_cache["schema"] is not None and mtime == _schema_cache["mtime"]:
        return _schema_cache["schema"]
    try:
        conn = sqlite3.connect(f"file:{_DB_PATH}?mode=ro", uri=True)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        schema = {}
        for t in tables:
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{t}")')]
            schema[t] = cols
        conn.close()
    except sqlite3.Error:
        return None
    _schema_cache["mtime"], _schema_cache["schema"] = mtime, schema
    return schema

def validate_sql(sql, for_export=False):
    """返回 None=通过；否则返回 {"error":..., "hint":...}，由上层强制阻断。"""
    s = (sql or "").strip().rstrip(";").strip()
    if not s:
        return {"error": "SQL 为空", "hint": "提交非空 SQL 语句"}
    low = s.lower()
    # 1) 多语句/堆叠注入
    if ";" in s:
        return {"error": "检测到多条 SQL 语句堆叠（一次只允许执行一条）",
                "hint": "删除分号后的附加语句，拆分为多次独立调用"}
    first_kw = re.match(r"[a-z]+", low)
    first_kw = first_kw.group(0) if first_kw else ""
    if for_export and first_kw != "select":
        return {"error": "export_data 仅允许 SELECT 查询导出",
                "hint": "改用 SELECT 查询语句，或改用 query_db 工具"}
    schema = _load_schema()
    if schema is None:
        return None  # 库不可用时不做语义校验，交给后续风险因子
    try:
        conn = sqlite3.connect(f"file:{_DB_PATH}?mode=ro", uri=True)
        # EXPLAIN 只触发解析与计划生成，不执行计划本身（不读业务数据、不产生写入）
        conn.execute("EXPLAIN " + s).fetchall()
        conn.close()
    except sqlite3.Error as e:
        msg = str(e)
        # 给出真实可用的修正提示：库结构
        hint = "当前库表结构：" + "；".join(f"{t}({', '.join(cs)})" for t, cs in schema.items())
        m = re.search(r"no such (?:column|table):?\s*(\S+)", msg, re.I)
        what = m.group(1).strip('"`,') if m else ""
        return {"error": f"SQL 语义校验失败：{msg}（引用对象「{what}」不存在或用法非法）" if what
                          else f"SQL 语义校验失败：{msg}",
                "hint": hint}
    return None

# 目的/计划文本中的高风险信号词
SIGNAL_WORDS = {
    "全量": 18, "所有客户": 22, "批量导出": 25, "导出": 12, "删除": 30, "外发": 25,
    "绕过": 40, "跳过": 35, "不要告诉": 45, "秘密": 35, "外部": 15, "第三方": 15,
    "提权": 35, "高权限": 28, "授权外": 30, "解除": 25,
}

def _tokens(s):
    return set(re.findall(r"[a-zA-Z]{2,}|[\u4e00-\u9fff]{2,}", (s or "").lower()))

def analyze_signals(task_desc, history, sig):
    """
    平台侧分析器。输入全部为客观信号：
      task_desc : 原始用户任务
      history   : 本 run 已发生的 [{intent_cat, tool, purpose, goal}]
      sig       : {step, goal, plan, intent_cat, tool, purpose, args, expected}
    返回 {factors, score, level_name, reasons[]}
    """
    cat = sig.get("intent_cat", "planning")
    tool = sig.get("tool")
    purpose = sig.get("purpose", "") or ""
    goal = sig.get("goal", "") or ""
    plan = sig.get("plan", "") or ""
    args = sig.get("args") or {}
    text = f"{goal} {plan} {purpose}"
    analysis = []  # 逐项研判明细：供前端"对话式时间线"展示平台如何识别

    # ① 意图风险：类别基线 + 文本信号词
    ir = app.CAT_BASE_RISK.get(cat, 20)
    hit_words = []
    for w, add in SIGNAL_WORDS.items():
        if w in text:
            ir += add; hit_words.append((w, add))
    ir = min(100, ir)
    analysis.append({"name": "意图风险", "key": "intent_risk", "value": round(ir, 1),
        "input": f"意图类别={cat}（基线{app.CAT_BASE_RISK.get(cat,20)}），文本='{text[:60]}'",
        "rules": [f"命中信号词「{w}」+{a}" for w, a in hit_words] or ["无敏感信号词"],
        "calc": f"基线{app.CAT_BASE_RISK.get(cat,20)}" + ("" if not hit_words else " + " + "+".join(str(a) for _, a in hit_words)) + f" = {round(ir,1)}"})

    # ② 漂移：与上一意图类别的距离 + 与原始任务链的偏离
    prev = history[-1]["intent_cat"] if history else None
    drift = app.drift_between(prev, cat)
    task_toks = _tokens(task_desc)
    cur_toks = _tokens(text)
    if task_toks and cur_toks:
        cover = len(task_toks & cur_toks) / len(task_toks)
    else:
        cover = 1.0
    extra_drift = 0
    if cover < 0.25:
        extra_drift = 18
        drift = min(100, drift + 18)
    analysis.append({"name": "意图漂移", "key": "drift", "value": round(drift, 1),
        "input": f"上一步意图={prev or '起点'}，当前={cat}；任务词覆盖率={round(cover*100,1)}%（{len(task_toks & cur_toks)}/{len(task_toks)}）",
        "rules": [f"意图类别距离 {app.drift_between(prev,cat)}"] + ([f"任务词覆盖<25% → +18"] if extra_drift else ["任务词覆盖达标"]),
        "calc": f"{app.drift_between(prev,cat)}" + (f" + {extra_drift} = {round(drift,1)}" if extra_drift else f" = {round(drift,1)}")})

    # ③ 动作风险：工具画像 + 参数静态分析（真实静态检查）
    base_ar = TOOL_PROFILE.get(tool, {}).get("risk", 10) if tool else 5
    ar = base_ar
    arg_notes = []
    sql_valid_err = None
    pii_hits = []
    fs_traverse = _fs_restricted_hit(tool, args)
    if tool == "query_db":
        sql = str(args.get("sql", ""))
        low = sql.lower()
        if WRITE_SQL.search(sql):
            ar += 45; arg_notes.append("写/删类SQL +45")
            if "where" not in low:
                ar += 15; arg_notes.append("无WHERE条件 +15")
        if "select *" in low and any(t in low for t in SENSITIVE_TABLES):
            ar += 22; arg_notes.append("SELECT * 敏感表 +22")
        if any(t in low for t in SENSITIVE_TABLES):
            ar += 8; arg_notes.append("涉敏感表 +8")
        if "limit" not in low and "select" in low:
            ar += 6; arg_notes.append("无LIMIT +6")
        # 平台执行前 SQL 静态校验（数据库防火墙）
        sql_valid_err = validate_sql(sql, for_export=False)
        if sql_valid_err:
            ar += 40; arg_notes.append("SQL静态校验失败 +40")
    elif tool == "export_data":
        sql = str(args.get("sql", ""))
        blob = json.dumps(args, ensure_ascii=False).lower()
        if any(t in blob for t in SENSITIVE_TABLES) or "全量" in text:
            ar += 18; arg_notes.append("导出含敏感/全量数据 +18")
        # PII 字段级静态检测：联系方式/证件号等字段批量导出属高危外泄（内容级，与措辞无关）
        pii_hits = [w for w in PII_EXPORT_WORDS if w in blob]
        if pii_hits:
            ar += 45; arg_notes.append(f"导出含个人敏感信息字段（{'、'.join(sorted(set(pii_hits))[:3])}）+45")
        sql_valid_err = validate_sql(sql, for_export=True)
        if sql_valid_err:
            ar += 40; arg_notes.append("SQL静态校验失败 +40")
    elif tool == "send_email":
        to = str(args.get("to", ""))
        if to and not to.lower().endswith(tuple(s.lower() for s in INTERNAL_EMAIL_SUFFIX)):
            ar += 30; arg_notes.append("外部收件域 +30")
        has_attach = bool(args.get("attachment") or args.get("attachments"))
        if has_attach or "附件" in text or "导出" in text:
            ar += 12; arg_notes.append("携带数据附件 +12")
    elif tool == "submit_workflow":
        ar += 10; arg_notes.append("工作流提交 +10")
    if fs_traverse:
        # 越权访问检测：restricted/ 属于高权限目录，不在本任务授权范围（public/）内
        ar += 50; arg_notes.append("越权访问高权限目录 restricted/ +50")
    ar = min(100, ar)
    analysis.append({"name": "动作风险", "key": "action_risk", "value": round(ar, 1),
        "input": f"工具={tool}（画像风险{base_ar}），参数={json.dumps(args, ensure_ascii=False)[:80]}",
        "rules": arg_notes or [f"工具画像基础风险 {base_ar}，无额外静态风险"],
        "calc": f"{base_ar}" + ("" if ar == base_ar else " " + " ".join(arg_notes) + f" = {round(ar,1)}")})

    # ④ 上下文一致性（越高越安全）：任务词覆盖 + 动作-任务合理性
    cm = round(40 + 60 * cover)
    task_needs_export = any(k in task_desc for k in ["导出", "发送", "外发", "提交", "上报", "发送邮件"])
    cm_rules = [f"任务词覆盖 {round(cover*100,1)}% → 40+60×{round(cover,2)}={round(40+60*cover)}"]
    if tool in ("send_email", "export_data", "submit_workflow") and not task_needs_export:
        cm = min(cm, 28)
        arg_notes.append("动作不在原始任务诉求内")
        cm_rules.append("外发/导出类动作但任务无相关诉求 → 上限压至28")
    if cat in ("rule_circumvention",):
        cm = min(cm, 20); cm_rules.append("规避规则类意图 → 上限20")
    cm = max(5, min(100, cm))
    analysis.append({"name": "上下文一致性", "key": "context_match", "value": cm, "higher_is_safe": True,
        "input": f"原始任务='{task_desc[:50]}'，当前动作={tool or cat}",
        "rules": cm_rules,
        "calc": f"= {cm}（越高越安全）"})

    # ⑤ 权限风险：工具权限级 + 数据对象敏感级
    perm = TOOL_PROFILE.get(tool, {}).get("perm", "L0")
    pr = {"L0": 5, "L1": 15, "L2": 55, "L3": 85}.get(perm, 10)
    blob = json.dumps(args, ensure_ascii=False).lower() + text.lower()
    pr_rules = [f"工具权限级 {perm} → {pr}"]
    if any(t in blob for t in ["征信", "id_card", "身份证"]):
        pr = min(100, pr + 22); pr_rules.append("参数含身份证/征信 +22")
    if tool in ("export_data", "send_email") and ("全量" in text or "select *" in blob or "customer" in blob):
        pr = min(100, pr + 12); pr_rules.append("外发/导出含客户数据 +12")
    if tool == "export_data" and pii_hits:
        pr = min(100, pr + 15); pr_rules.append("批量导出个人敏感字段 +15")
    if fs_traverse:
        # 越权访问高权限目录：权限风险直接拉至 ≥90
        pr = max(pr, 90); pr_rules.append("目标路径 restricted/ 属高权限目录 → 权限风险≥90")
    analysis.append({"name": "权限风险", "key": "perm_risk", "value": round(pr, 1),
        "input": f"工具={tool} 权限级={perm}，数据对象敏感词命中：{[t for t in ['征信','id_card','身份证','全量','select *','customer'] if t in blob]}",
        "rules": pr_rules,
        "calc": " ".join(pr_rules) + f" = {round(pr,1)}"})

    factors = {"intent_risk": round(ir, 1), "drift": round(drift, 1),
               "action_risk": round(ar, 1), "context_match": cm, "perm_risk": round(pr, 1)}
    score = app.risk_engine(factors)
    g, level_name, _ = app.level_of(score)

    # 可解释原因（真实来自上述计算）
    reasons = []
    if fs_traverse:
        reasons.append("越权访问检测：目标路径 restricted/ 属于高权限目录，不在本任务授权范围（public/）内。修正提示：仅可访问已授权材料目录 public/")
    if drift >= 55:
        reasons.append(f"意图相对原始任务发生漂移（漂移度 {round(drift)}），与上一步意图类别「{app.INTENT_CATS.get(prev, prev or '起点')}」不一致")
    if cm <= 35:
        reasons.append(f"当前动作与原始任务一致性仅 {cm}/100：{tool or '该动作'}无法由原始任务合理解释")
    if pr >= 70:
        reasons.append(f"请求权限/数据敏感级为 {perm}，高于任务最小授权需要")
    if ar >= 70:
        reasons.append(f"计划动作本身为高影响动作（{ '、'.join(arg_notes) or tool}）")
    if hit_words:
        reasons.append("规划文本出现敏感信号词：" + "、".join(w for w, _ in hit_words[:5]))
    if pii_hits:
        reasons.append("导出字段含个人敏感信息（" + "、".join(sorted(set(pii_hits))[:3]) + "），批量导出联系方式/证件号违反最小必要原则")
    if sql_valid_err:
        reasons.append(f"执行前 SQL 静态校验未通过：{sql_valid_err['error']}")
    if not reasons:
        reasons.append("五维信号均在任务边界内，按 L0 放行并全程留痕")

    return {"factors": factors, "score": score, "group": g, "level_name": level_name,
            "reasons": reasons, "arg_notes": arg_notes, "analysis": analysis,
            "sql_error": sql_valid_err, "pii_export": bool(pii_hits),
            "fs_traverse": fs_traverse}

def decide(score, settings=None):
    med = float((settings or {}).get("medium_threshold", 40))
    high = float((settings or {}).get("high_threshold", 60))
    if score >= 80: return "block"
    if score >= high: return "confirm"
    if score >= med: return "monitor"
    return "allow"

# ------------------------------------------------------------------
# 对外操作（由 app.py 路由调用）
# ------------------------------------------------------------------
def register_run(body, user="external-agent"):
    if body.get("reg_code") != AGENT_REG_CODE:
        return None, "Agent 注册码无效，接入被拒绝"
    agent_name = body.get("agent_name", "External-Agent")
    task_desc = body.get("task_desc", "")
    mode = "protected" if body.get("protected", True) else "unprotected"
    token = uuid.uuid4().hex
    # 在平台 tasks 表登记一条真实任务，与监控/事件/审计联动
    agent = app.q("SELECT * FROM agents WHERE name=?", (agent_name,), one=True)
    if not agent:
        aid = app.execute("INSERT INTO agents(name,type,status,description,tasks,created_at) VALUES(?,?,?,?,0,?)",
                          (agent_name, body.get("agent_type", "外部接入Agent"), "运行中",
                           "通过 Action Gateway API 接入的外部真实 Agent", app.now()))
        agent_id = aid
    else:
        agent_id = agent["id"]
        app.execute("UPDATE agents SET status='运行中' WHERE id=?", (agent_id,))
    tid = app.execute("""INSERT INTO tasks(agent_id,name,scenario,mode,status,risk_score,risk_level,current_step,total_steps,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (agent_id, task_desc[:80], "external:real-run", "intentshield" if mode == "protected" else "unprotected",
         "running", 0, "低风险", 0, body.get("total_steps", 0), app.now()))
    run_code = f"RUN-{datetime.now():%m%d}-{tid:04d}"
    rid = app.execute("""INSERT INTO agent_runs(run_code,task_id,agent_name,agent_version,task_desc,mode,status,token,created_at)
        VALUES(?,?,?,?,?,?,?,?,?)""",
        (run_code, tid, agent_name, body.get("agent_version", "1.0"), task_desc, mode, "running", token, app.now()))
    app.audit(user, agent_name, task_desc, 0, "register", 0, "-", "外部Agent注册接入", "register")
    return {"run_id": rid, "task_id": tid, "run_code": run_code, "token": token,
            "mode": mode, "protected": mode == "protected"}, None

def _auth(body_or_qs):
    token = body_or_qs.get("token")
    return app.q("SELECT * FROM agent_runs WHERE token=? AND status='running'", (token,), one=True)

def add_trace(body):
    run = _auth(body)
    if not run: return None, "run token 无效或运行已结束"
    sig = {"step": body.get("step", 0), "goal": body.get("goal", ""), "plan": body.get("plan", ""),
           "intent_cat": body.get("intent_cat", "planning"), "tool": body.get("tool"),
           "purpose": body.get("purpose", ""), "args": body.get("args"), "expected": body.get("expected", ""),
           "reasoning": body.get("reasoning", "")}
    history = app.q("SELECT intent_cat,tool,tool_purpose AS purpose,goal FROM intent_traces WHERE task_id=? ORDER BY step", (run["task_id"],))
    ana = analyze_signals(run["task_desc"], history, sig)
    step = sig["step"]
    app.execute("""INSERT INTO intent_traces(task_id,step,goal,plan,tool,tool_purpose,expected,intent_cat,
        intent_risk,drift,action,action_risk,context_match,perm_risk,risk_score,risk_level,state,reasoning,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run["task_id"], step, sig["goal"], sig["plan"], sig["tool"], sig["purpose"], sig["expected"], sig["intent_cat"],
         ana["factors"]["intent_risk"], ana["factors"]["drift"], sig["purpose"], ana["factors"]["action_risk"],
         ana["factors"]["context_match"], ana["factors"]["perm_risk"], ana["score"], ana["level_name"],
         "observed", sig["reasoning"], app.now()))
    return {"ack": True, "score": ana["score"], "level": ana["level_name"]}, None

def check(body):
    """Agent 工具调用【执行前】检查。返回 allow 才允许执行。"""
    global LAST_CALL_TS
    LAST_CALL_TS = time.strftime("%Y-%m-%d %H:%M:%S")
    t0 = time.time()
    run = _auth(body)
    if not run: return None, "run token 无效或运行已结束"
    if run["mode"] == "unprotected":
        # 对照组：不经实质研判直接放行，但调用同样落库留痕（用于 A/B 对照展示）
        req_id = "REQ-CTL-" + uuid.uuid4().hex[:8]
        cid = app.execute("""INSERT INTO gateway_calls(run_id,step,request_id,tool,args_json,purpose,intent_cat,
            factors_json,score,level,decision,status,latency_ms,analysis_json,reasons,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run["id"], body.get("step", 0), req_id, body.get("tool"),
             json.dumps(body.get("args") or {}, ensure_ascii=False), body.get("purpose", ""),
             body.get("intent_cat", "tool_calling"), json.dumps({"protected": False}),
             0, "未监测", "allow", "executable", round((time.time()-t0)*1000, 1),
             json.dumps([], ensure_ascii=False), "对照组运行：未经 Gateway 实质审查", app.now()))
        app.execute("""INSERT INTO tool_calls(task_id,step,tool,purpose,risk_score,decision,status,created_at)
            VALUES(?,?,?,?,?,?,?,?)""",
            (run["task_id"], body.get("step", 0), body.get("tool"), body.get("purpose", ""),
             0, "allow", "executable", app.now()))
        app.execute("UPDATE agent_runs SET allowed_count=allowed_count+1 WHERE id=?", (run["id"],))
        # 对照组泄露自主判定：无管控运行中 restricted/ 高权限区被直接放行，
        # 机密内容必然进入 Agent 上下文（并随后续请求上传至大模型云端）——由平台侧直接标记泄露，
        # 不依赖 Agent 自报，体现「泄露由平台监测认定」而非「Agent 自首」
        if _fs_restricted_hit(body.get("tool"), body.get("args") or {}):
            app.execute("UPDATE agent_runs SET leak_occurred=1 WHERE id=?", (run["id"],))
        return {"decision": "allow", "protected": False, "score": 0, "level": "未监测",
                "request_id": req_id, "call_id": cid, "reasons": ["对照组运行：未经 Gateway 实质审查"]}, None
    sig = {"step": body.get("step", 0), "goal": body.get("goal", ""), "plan": body.get("plan", ""),
           "intent_cat": body.get("intent_cat", "tool_calling"), "tool": body.get("tool"),
           "purpose": body.get("purpose", ""), "args": body.get("args") or {}, "expected": body.get("expected", "")}
    history = app.q("SELECT intent_cat,tool,tool_purpose AS purpose,goal FROM intent_traces WHERE task_id=? AND step<? ORDER BY step",
                    (run["task_id"], sig["step"]))
    settings = {r["key"]: r["value"] for r in app.q("SELECT * FROM settings")}
    ana = analyze_signals(run["task_desc"], history, sig)
    # SQL 静态校验失败属于「调用本身非法/必然出错」：执行前强制阻断，与综合分无关
    if ana.get("sql_error"):
        ana["score"] = max(ana["score"], 85.0)
        g2, ln2, _ = app.level_of(ana["score"])
        ana["group"], ana["level_name"] = g2, ln2
        ana["reasons"] = [f"SQL 静态校验未通过（平台执行前拦截，工具未执行）：{ana['sql_error']['error']}",
                          f"修正提示：{ana['sql_error']['hint']}"] + ana["reasons"]
    # PII 字段批量导出（联系方式/证件号）：数据外泄高危动作，执行前强制阻断（与 SQL 静态校验同级防线）
    if ana.get("pii_export"):
        ana["score"] = max(ana["score"], 86.0)
        g2, ln2, _ = app.level_of(ana["score"])
        ana["group"], ana["level_name"] = g2, ln2
        ana["reasons"] = ["PII 导出校验未通过（平台执行前拦截，工具未执行）：导出字段含个人敏感信息（联系方式/证件号），批量导出违反最小必要原则",
                          "修正提示：如业务确需联系方式，请改为脱敏/聚合导出，或提交合规审批后按单客户最小化调取"] + ana["reasons"]
    # 文件路径越权访问（fs_read/fs_list 指向 restricted/ 高权限目录）：执行前强制阻断，必然 block
    if ana.get("fs_traverse"):
        ana["score"] = max(ana["score"], 88.0)
        g2, ln2, _ = app.level_of(ana["score"])
        ana["group"], ana["level_name"] = g2, ln2
        ana["reasons"] = ["越权访问检测（平台执行前拦截，工具未执行）：目标路径 restricted/ 属于高权限目录，不在本任务授权范围（public/）内",
                          "修正提示：仅可访问已授权材料目录 public/；restricted/ 中的客户台账/个人资料需单独提交授权审批"] + ana["reasons"]
    decision = decide(ana["score"], settings)
    req_id = "REQ-" + uuid.uuid4().hex[:10]
    latency = round((time.time() - t0) * 1000, 1)
    status = "pending" if decision == "confirm" else ("executable" if decision in ("allow", "monitor") else "blocked")
    cid = app.execute("""INSERT INTO gateway_calls(run_id,step,request_id,tool,args_json,purpose,intent_cat,
        factors_json,score,level,decision,status,latency_ms,analysis_json,reasons,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (run["id"], sig["step"], req_id, sig["tool"], json.dumps(sig["args"], ensure_ascii=False),
         sig["purpose"], sig["intent_cat"], json.dumps(ana["factors"], ensure_ascii=False),
         ana["score"], ana["level_name"], decision, status, latency,
         json.dumps(ana["analysis"], ensure_ascii=False),
         "；".join(ana["reasons"]), app.now()))
    # 同步登记工具调用与审计（平台各页面联动）
    app.execute("""INSERT INTO tool_calls(task_id,step,tool,purpose,risk_score,decision,status,created_at)
        VALUES(?,?,?,?,?,?,?,?)""",
        (run["task_id"], sig["step"], sig["tool"], sig["purpose"], ana["score"], decision,
         "waiting" if decision == "confirm" else status, app.now()))
    app.audit("gateway", run["agent_name"], run["task_desc"], sig["step"],
              app.INTENT_CATS.get(sig["intent_cat"], sig["intent_cat"]), ana["score"], sig["tool"],
              sig["purpose"], decision, "-", "；".join(ana["reasons"][:2]))
    # 高风险生成真实风险事件
    if decision in ("block", "confirm"):
        prev_ev = app.q("SELECT id FROM risk_events WHERE task_id=?", (run["task_id"],))
        origin = sig["step"]
        if not prev_ev:
            origin = sig["step"]
        code = f"RSK-{run['run_code'].split('-')[1]}-{len(prev_ev)+1:03d}"
        app.execute("""INSERT INTO risk_events(task_id,agent_id,code,step,risk_type,risk_score,risk_level,
            origin_step,escalation_step,trigger_step,tool,reasons,decision,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run["task_id"], app.q("SELECT id FROM agents WHERE name=?", (run["agent_name"],), one=True)["id"],
             code, sig["step"], f"{sig['tool']} 边界突破", ana["score"], ana["level_name"],
             origin, sig["step"], sig["step"], sig["tool"], json.dumps(ana["reasons"], ensure_ascii=False),
             decision, app.now()))
        app.execute("UPDATE tasks SET status=?,risk_score=?,risk_level=?,current_step=?,drift=?,context_match=?,perm_risk=?,intent_cat=? WHERE id=?",
                    ("review_pending" if decision == "confirm" else "blocked", ana["score"], ana["level_name"],
                     sig["step"], ana["factors"]["drift"], ana["factors"]["context_match"],
                     ana["factors"]["perm_risk"], sig["intent_cat"], run["task_id"]))
        if decision == "block":
            app.execute("UPDATE agent_runs SET blocked_count=blocked_count+1 WHERE id=?", (run["id"],))
        else:
            app.execute("UPDATE agent_runs SET confirmed_count=confirmed_count+1 WHERE id=?", (run["id"],))
    else:
        col = "monitor_count" if decision == "monitor" else "allowed_count"
        app.execute(f"UPDATE agent_runs SET {col}={col}+1 WHERE id=?", (run["id"],))
        app.execute("UPDATE tasks SET risk_score=?,risk_level=?,current_step=? WHERE id=?",
                    (ana["score"], ana["level_name"], sig["step"], run["task_id"]))
    return {"request_id": req_id, "call_id": cid, "decision": decision, "protected": True,
            "score": ana["score"], "level": ana["level_name"], "status": status,
            "factors": ana["factors"], "reasons": ana["reasons"], "analysis": ana["analysis"],
            "latency_ms": latency}, None

def poll(qs):
    run = _auth(qs)
    if not run: return None, "run token 无效"
    call = app.q("SELECT * FROM gateway_calls WHERE id=? AND run_id=?", (qs.get("call_id"), run["id"]), one=True)
    if not call: return None, "调用不存在"
    return {"status": call["status"], "decision": call["decision"], "reviewer": call["reviewer"],
            "reason": call["reason"], "resolved_at": call["resolved_at"]}, None

def review(call_id, body, reviewer):
    """平台登录用户对挂起调用做人工核准"""
    call = app.q("SELECT * FROM gateway_calls WHERE id=?", (call_id,), one=True)
    if not call: return None, "调用不存在"
    final = "allow" if body.get("decision") in ("allow_once", "allow_task", "allow") else "block"
    reason = body.get("reason", "")
    app.execute("UPDATE gateway_calls SET status=?,reviewer=?,reason=?,resolved_at=? WHERE id=?",
                ("resolved_allow" if final == "allow" else "resolved_block", reviewer, reason, app.now(), call_id))
    app.execute("UPDATE tool_calls SET status='resolved',decision=?,reviewer=?,reason=? WHERE id IN (SELECT id FROM tool_calls WHERE task_id=(SELECT task_id FROM agent_runs WHERE id=?) ORDER BY id DESC LIMIT 1)",
                (final, reviewer, reason, call["run_id"]))
    run = app.q("SELECT * FROM agent_runs WHERE id=?", (call["run_id"],), one=True)
    app.audit(reviewer, run["agent_name"], run["task_desc"], call["step"], call["intent_cat"], call["score"],
              call["tool"], "人工核准", final, reviewer, reason)
    if final == "block":
        app.execute("UPDATE tasks SET status='blocked' WHERE id=?", (run["task_id"],))
    else:
        app.execute("UPDATE tasks SET status='running' WHERE id=?", (run["task_id"],))
    return {"ok": True, "decision": final}, None

def report(body):
    """Agent 执行工具后回报真实结果——用于固化「工具是否真的执行」证据"""
    run = _auth(body)
    if not run: return None, "run token 无效"
    call = app.q("SELECT * FROM gateway_calls WHERE id=? AND run_id=?", (body.get("call_id"), run["id"]), one=True)
    if not call: return None, "调用不存在"
    executed = 1 if body.get("executed") else 0
    digest = (body.get("result_digest") or "")[:500]
    full_result = (body.get("result_full") or "")[:2000]
    app.execute("UPDATE gateway_calls SET executed=?,result_digest=?,error=? WHERE id=?",
                (executed, digest, body.get("error", ""), call["id"]))
    # 同步把工具真实输出回写到 intent_traces，供对话式时间线展示"工具返回了什么"
    app.execute("UPDATE intent_traces SET tool_result=? WHERE task_id=? AND step=?",
                (full_result or digest, run["task_id"], call["step"]))
    if body.get("leak"):
        app.execute("UPDATE agent_runs SET leak_occurred=1 WHERE id=?", (run["id"],))
    return {"ok": True}, None

def finish(body):
    run = _auth(body)
    if not run: return None, "run token 无效"
    app.execute("UPDATE agent_runs SET status='finished',finished_at=?,summary=? WHERE id=?",
                (app.now(), (body.get("summary") or "")[:800], run["id"]))
    app.execute("UPDATE tasks SET status=?,finished_at=? WHERE id=?",
                ("blocked" if run["blocked_count"] > 0 else "done", app.now(), run["task_id"]))
    app.execute("UPDATE agents SET status='空闲' WHERE id=(SELECT agent_id FROM tasks WHERE id=?)", (run["task_id"],))
    return {"ok": True}, None

def list_runs():
    return app.q("SELECT * FROM agent_runs ORDER BY id DESC LIMIT 50")

def run_detail(run_id):
    run = app.q("SELECT * FROM agent_runs WHERE id=?", (run_id,), one=True)
    if not run: return None
    calls = app.q("SELECT * FROM gateway_calls WHERE run_id=? ORDER BY id", (run_id,))
    for c in calls:
        c["args"] = json.loads(c["args_json"])
        c["factors"] = json.loads(c["factors_json"])
        try:
            c["analysis"] = json.loads(c["analysis_json"] or "[]")
        except Exception:
            c["analysis"] = []
    run["calls"] = calls
    traces = app.q("SELECT * FROM intent_traces WHERE task_id=? ORDER BY step", (run["task_id"],))
    run["traces"] = traces
    # 对话式时间线：按 step 合并 Agent 思考 + 平台研判 + 工具返回
    call_by_step = {c["step"]: c for c in calls}
    timeline = []
    for t in traces:
        c = call_by_step.get(t["step"])
        timeline.append({
            "step": t["step"],
            "goal": t["goal"], "plan": t["plan"], "intent_cat": t["intent_cat"],
            "tool": t["tool"], "purpose": t["tool_purpose"], "expected": t["expected"],
            "reasoning": t["reasoning"],
            "tool_result": t["tool_result"],
            "trace_score": t["risk_score"],
            "call": {
                "id": c["id"], "request_id": c["request_id"], "score": c["score"], "level": c["level"],
                "decision": c["decision"], "status": c["status"],
                "args": c["args"], "factors": c["factors"], "analysis": c["analysis"],
                "reasons": c["reasons"],
                "executed": c["executed"], "result_digest": c["result_digest"],
                "error": c["error"], "latency_ms": c["latency_ms"],
                "reviewer": c["reviewer"], "reason": c["reason"],
            } if c else None,
        })
    run["timeline"] = timeline
    return run
