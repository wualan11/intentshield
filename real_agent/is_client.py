# -*- coding: utf-8 -*-
"""
is_client.py — 智链盾 Action Gateway 接入 SDK
=============================================
任何外部 Agent / 框架（自研 ReAct、LangChain、AutoGen……）接入方式：

    from is_client import Shield
    shield = Shield(base_url="http://127.0.0.1:8800")
    run = shield.register(agent_name="My-Agent", task_desc=task)
    # ... 每一步上报意图轨迹 ...
    shield.trace(step=3, goal=..., intent_cat="tool_calling", ...)
    # 调用任何工具【之前】必须过闸：
    result = shield.check(step=3, tool="query_db", args={"sql": sql}, purpose=...)
    if result["decision"] == "block":
        raise PermissionError(result["reasons"])      # 工具绝不执行
    if result["decision"] == "confirm":
        shield.wait_for_human(result["call_id"])      # 真实阻塞，等待平台人工核准
    rows = my_real_tool.query_db(sql)                 # 放行后才真正执行
    shield.report_executed(result["call_id"], digest=...)

纯标准库实现；与平台仅通过 HTTP+JSON 通信（可抓包验证）。
"""
import json, time, urllib.request, urllib.error

REG_CODE = "intentshield-agent-2026"

class GatewayDenied(Exception):
    """Gateway 阻断：工具调用被拒绝，Agent 不得执行该工具。"""
    def __init__(self, decision, reasons, request_id, score):
        super().__init__(f"[{decision}] {request_id} score={score}：{'; '.join(reasons)}")
        self.decision, self.reasons, self.request_id, self.score = decision, reasons, request_id, score

class HumanRejected(GatewayDenied):
    """人工审核拒绝。"""

class GatewayFrozen(Exception):
    """Gateway 不可达，Agent 已冻结所有工具调用（fail-closed）。"""

class Shield:
    def __init__(self, base_url="http://127.0.0.1:8800", timeout=30, max_freeze=300):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.max_freeze = max_freeze  # 最长冻结秒数，超时则放弃
        self.run_id = self.task_id = self.run_code = self.token = None
        self.protected = True
        self._frozen = False

    def _post(self, path, payload, critical=True):
        """发送 POST；Gateway 不可达时进入 fail-closed 冻结（重试到恢复或超时）。"""
        url = self.base + path
        data = json.dumps(payload).encode("utf-8")
        first_err = None
        for _ in range(self.max_freeze):
            try:
                req = urllib.request.Request(url, data=data,
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    if self._frozen:
                        self._frozen = False
                        print(f"  [Shield] 网关已恢复，Agent 解冻继续执行", flush=True)
                    return json.loads(r.read().decode("utf-8"))
            except (urllib.error.URLError, ConnectionError, OSError) as e:
                if first_err is None:
                    first_err = str(e)
                if not self._frozen:
                    self._frozen = True
                    if critical:
                        print(f"  [Shield] FAIL-CLOSED：网关不可达，Agent 冻结所有工具调用（{first_err}）", flush=True)
                    time.sleep(2)
                    continue
                time.sleep(2)
        # 冻结超时：关键路径抛异常终止，非关键路径返回空
        if critical:
            raise GatewayFrozen(f"网关持续不可达 {self.max_freeze}s，Agent 安全终止（fail-closed）")
        return None

    def _get(self, path, critical=True):
        """发送 GET；同样支持 fail-closed 冻结。"""
        url = self.base + path
        first_err = None
        for _ in range(self.max_freeze):
            try:
                with urllib.request.urlopen(url, timeout=self.timeout) as r:
                    if self._frozen:
                        self._frozen = False
                    return json.loads(r.read().decode("utf-8"))
            except (urllib.error.URLError, ConnectionError, OSError) as e:
                if first_err is None: first_err = str(e)
                if not self._frozen:
                    self._frozen = True
                    if critical:
                        print(f"  [Shield] FAIL-CLOSED：网关不可达，Agent 冻结（{first_err}）", flush=True)
                time.sleep(2)
        if critical:
            raise GatewayFrozen(f"网关持续不可达 {self.max_freeze}s，Agent 安全终止（fail-closed）")
        return None

    def register(self, agent_name, task_desc, protected=True, agent_version="1.0-real",
                 agent_type="外部接入Agent", total_steps=0):
        r = self._post("/api/gateway/register", {
            "reg_code": REG_CODE, "agent_name": agent_name, "agent_version": agent_version,
            "agent_type": agent_type, "task_desc": task_desc, "protected": protected,
            "total_steps": total_steps})
        self.run_id, self.task_id = r["run_id"], r["task_id"]
        self.run_code, self.token, self.protected = r["run_code"], r["token"], r["protected"]
        return r

    def trace(self, step, goal, plan="", intent_cat="planning", tool=None,
              purpose="", expected="", args=None, reasoning=""):
        return self._post("/api/gateway/trace", {
            "token": self.token, "step": step, "goal": goal, "plan": plan,
            "intent_cat": intent_cat, "tool": tool, "purpose": purpose,
            "expected": expected, "args": args or {}, "reasoning": reasoning})

    def check(self, step, goal, tool, args, purpose, intent_cat="tool_calling",
              plan="", expected=""):
        """执行前检查。返回决策；block 时抛 GatewayDenied（工具绝不执行）。"""
        r = self._post("/api/gateway/check", {
            "token": self.token, "step": step, "goal": goal, "plan": plan,
            "intent_cat": intent_cat, "tool": tool, "purpose": purpose,
            "args": args or {}, "expected": expected})
        if r["decision"] == "block":
            raise GatewayDenied(r["decision"], r.get("reasons", []), r["request_id"], r["score"])
        return r

    def wait_for_human(self, call_id, on_update=None, poll_interval=1.5):
        """真实阻塞轮询，直到平台网页上的人工审核完成。"""
        while True:
            r = self._get(f"/api/gateway/poll?token={self.token}&call_id={call_id}")
            if on_update: on_update(r)
            if r["status"].startswith("resolved"):
                if r["decision"] == "block":
                    raise HumanRejected("block", [f"人工拒绝：{r['reason'] or '审核员拒绝该调用'}"], "-", 0)
                return r
            time.sleep(poll_interval)

    def report_executed(self, call_id, digest="", leak=False, executed=True, error="", result_full=""):
        return self._post("/api/gateway/report", {
            "token": self.token, "call_id": call_id, "executed": executed,
            "result_digest": digest, "result_full": result_full,
            "leak": leak, "error": error})

    def finish(self, summary=""):
        return self._post("/api/gateway/finish", {"token": self.token, "summary": summary})

    def propose(self, step, tool, blocked_reason, proposed_action, justification):
        """Agent 被阻断后正式发起策略放宽提案（对应 NVIDIA agent-proposed policy updates）。
        平台收到后进入人工审批队列；审批通过前 Agent 不得执行被阻断的工具。"""
        return self._post("/api/gateway/propose", {
            "token": self.token, "step": step, "tool": tool,
            "blocked_reason": blocked_reason, "proposed_action": proposed_action,
            "justification": justification}, critical=False)

    @property
    def frozen(self):
        """Agent 当前是否处于 fail-closed 冻结状态。"""
        return self._frozen
