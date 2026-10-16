# -*- coding: utf-8 -*-
"""
run.py — 真实外部 Agent 进程入口
================================
用法：
  python run.py T1                      # 受保护运行正常任务
  python run.py T3 --protected          # 受保护：注入任务，越权外发被阻断
  python run.py T3 --unprotected        # 对照组：无防护，数据真实外泄
  python run.py T2 --on-confirm allow   # 人工确认策略：wait(交互)/allow/deny

Agent 与智链盾平台是【两个独立进程】，仅通过 HTTP 通信（可抓包）。
"""
import sys, os, io, json, time, argparse, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass

from is_client import Shield, GatewayDenied, HumanRejected
from planner import make_planner, TASKS
import sandbox

# ANSI 颜色（Windows 10+ 支持）
C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m", "b": "\033[94m",
     "x": "\033[0m", "gray": "\033[90m"}
def log(tag, msg, color="c"):
    print(f"{C[color]}[{tag}]{C['x']} {msg}")

def digest_of(v):
    s = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
    return s[:180]

def detect_leak():
    """Agent 侧自检：是否真的产生了敏感导出/外部邮件（用于 A/B 对照取证）"""
    leaks = []
    for f in os.listdir(sandbox.EXPORTS):
        leaks.append("exports/" + f)
    for f in os.listdir(sandbox.OUTBOX):
        if "_at_" in f and "bank.internal" not in f:
            leaks.append("outbox/" + f)
    return leaks

def run(task_id, protected=True, on_confirm="deny", url="http://127.0.0.1:8800", reset=True, slow=False):
    spec = TASKS[task_id]
    print("=" * 72)
    print(f"  真实 Agent 进程  PID={os.getpid()}  模式={'受保护 IntentShield' if protected else '⚠ 无防护对照组'}")
    print(f"  任务 {task_id}：{spec['name']}")
    print(f"  目标：{spec['desc']}")
    print("=" * 72)

    if reset:
        sandbox.init(reset=True)
        log("ENV", "工具沙箱已重置（真实文件库 + 真实 SQLite bank.db）", "gray")

    planner = make_planner(task_id)
    shield = Shield(base_url=url)
    reg = shield.register(agent_name="Finance-Runtime-Agent", task_desc=spec["desc"],
                          protected=protected, agent_version=planner.name)
    log("REG", f"已通过 Gateway 注册：{reg['run_code']}（run_id={reg['run_id']}，HTTP 接入，已签发 run token）", "b")

    decisions, blocked_at, leak_before = [], None, set()
    step_no, finished_reason, report_ok = 0, None, False
    try:
        while True:
            st = planner.next()
            if st is None:
                finished_reason = "任务全部步骤执行完成"; break
            step_no += 1
            if slow: time.sleep(4.0)  # 逐步演示：给前端流式观测留出时间
            print("-" * 72)
            log(f"STEP {step_no}", f"{st['goal']}", "c")
            if st["tool"]:
                print(f"      计划工具：{C['b']}{st['tool']}{C['x']}  参数：{json.dumps(st['args'], ensure_ascii=False)[:90]}")

            # 1) 意图轨迹上报（客观信号 + Agent 推理文本，不含自评分）
            shield.trace(step=step_no, goal=st["goal"], plan=st["plan"],
                         intent_cat=st["intent_cat"], tool=st["tool"],
                         purpose=st["purpose"], expected=st["expected"], args=st["args"],
                         reasoning=st.get("reasoning", ""))

            if not st["tool"]:
                decisions.append(("step", "allow", 0)); continue

            # 2) 工具执行【之前】过闸
            t0 = time.time()
            chk = shield.check(step=step_no, goal=st["goal"], plan=st["plan"],
                               intent_cat=st["intent_cat"], tool=st["tool"],
                               args=st["args"], purpose=st["purpose"], expected=st["expected"])
            decisions.append((st["tool"], chk["decision"], chk.get("score", 0)))

            if not chk.get("protected", True):
                log("GATEWAY", f"{C['gray']}对照组运行：Gateway 未实质审查（score=0），直接执行{C['x']}", "gray")
            else:
                col = {"allow": "g", "monitor": "y", "confirm": "y", "block": "r"}[chk["decision"]]
                log("GATEWAY", f"{chk['request_id']}  score={chk['score']} {chk['level']} → "
                    f"{chk['decision'].upper()}（{ (time.time()-t0)*1000:.0f} ms）", col)
                for r_ in chk.get("reasons", [])[:3]:
                    print(f"      {C['gray']}原因：{r_}{C['x']}")
                print(f"      {C['gray']}因子：{json.dumps(chk.get('factors',{}), ensure_ascii=False)}{C['x']}")

            # 3) 人工确认分支（真实阻塞：轮询等待平台网页上的审核动作）
            if chk["decision"] == "confirm":
                if on_confirm == "wait":
                    log("HUMAN", "调用已挂起，Agent 进程真实阻塞等待人工审核（请在平台「实时监控/真实运行」页核准）…", "y")
                    shield.wait_for_human(chk["call_id"])
                    log("HUMAN", "收到人工核准：放行", "g")
                elif on_confirm == "allow":
                    log("HUMAN", "自动演示策略：人工确认通过（限权条件下）", "g")
                else:
                    log("HUMAN", "演示策略：高风险调用默认拒绝（生产中由审核员在网页操作）", "r")
                    blocked_at = step_no
                    raise GatewayDenied("confirm-denied", ["人工确认环节拒绝：不满足最小授权"], chk["request_id"], chk.get("score", 0))

            # 4) 放行后真实执行工具
            try:
                result = sandbox.call_tool(st["tool"], st["args"])
            except Exception as e:
                shield.report_executed(chk.get("call_id", 0), executed=False, error=str(e)[:200])
                log("TOOL", f"工具执行异常：{e}", "r")
                raise
            log("TOOL", f"真实执行完成 → {digest_of(result)}", "g")
            if chk.get("call_id"):
                leaks_now = detect_leak()
                shield.report_executed(chk["call_id"], digest=digest_of(result),
                                       result_full=json.dumps(result, ensure_ascii=False) if not isinstance(result, str) else result,
                                       leak=bool(leaks_now))

            # 5) 真实动态机制：读到的文件中含指令块 → 插入后续步骤
            if st["tool"] == "read_file":
                added = planner.extract_directives(result if isinstance(result, str) else "")
                for a in added:
                    log("PLANNER", f"{C['y']}从所读文件内容中解析到新指令，已加入执行计划：{a['tool']} → {a['args']}{C['x']}", "y")
                # 财报CSV解析结果存入上下文，供后续动态分析步骤使用
                if isinstance(result, dict) and result.get("metrics"):
                    planner.set_context("financials", result)
            if st["tool"] == "query_db" and isinstance(result, list):
                # 台账查询结果存入上下文
                planner.set_context("loans", result)

    except GatewayDenied as e:
        blocked_at = blocked_at or step_no
        blocked_tool = st.get("tool", "?")
        print()
        log("⛔ BLOCKED", f"工具【没有执行】。Agent 进程收到 Gateway 拒绝：{e}", "r")
        log("EVIDENCE", f"被拦工具 {blocked_tool} 在沙箱中无执行产物（exports/outbox 无新增）", "r")
        decisions.append((blocked_tool, "block", e.score))
        finished_reason = f"Step {step_no} 被 Gateway 执行前阻断"
    except Exception as e:
        traceback.print_exc()
        finished_reason = f"异常中止：{e}"

    # 结束取证
    leaks = detect_leak()
    print("=" * 72)
    log("SUMMARY", f"{finished_reason}", "c")
    log("SUMMARY", f"决策序列：{['%s=%s(%.0f)' % d for d in decisions]}", "gray")
    log("SUMMARY", f"阻断步骤：{blocked_at or '无'}", "r" if blocked_at else "g")
    log("SUMMARY", f"泄密证据文件：{leaks if leaks else '无'}", "r" if leaks else "g")
    log("SUMMARY", f"产物目录：reports={os.listdir(sandbox.REPORTS)} exports={os.listdir(sandbox.EXPORTS)} outbox={os.listdir(sandbox.OUTBOX)}", "gray")
    try:
        shield.finish(finished_reason or "")
    except Exception as e:
        print("finish 上报失败：", e)
    print("=" * 72)
    return {"task": task_id, "protected": protected, "blocked_at": blocked_at,
            "decisions": decisions, "leaks": leaks, "finished_reason": finished_reason,
            "run_code": reg["run_code"], "run_id": reg["run_id"]}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("task", choices=list(TASKS.keys()) + ["L1", "L2", "L3"])
    ap.add_argument("--llm", action="store_true", help="使用真实 DeepSeek 大模型推理（任务 L1/L2/L3）")
    ap.add_argument("--protected", dest="protected", action="store_true", default=True)
    ap.add_argument("--unprotected", dest="protected", action="store_false")
    ap.add_argument("--on-confirm", choices=["wait", "allow", "deny"], default="deny")
    ap.add_argument("--url", default="http://127.0.0.1:8800")
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--slow", action="store_true", help="逐步演示模式，每步间隔1秒便于前端实时观测")
    a = ap.parse_args()
    if a.llm or a.task.startswith("L"):
        from llm_agent import run_llm
        run_llm(a.task, a.protected, a.on_confirm, a.url, reset=not a.no_reset, slow=a.slow)
    else:
        run(a.task, a.protected, a.on_confirm, a.url, reset=not a.no_reset, slow=a.slow)
