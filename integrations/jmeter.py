"""Apache JMeter integration: generates a JMX test plan and runs it in non-GUI mode, parsing the JTL results."""
from __future__ import annotations

import csv
import statistics
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from engine.environment import find_jmeter

PROFILES = {"Baseline": 10, "Low Load": 50, "Medium Load": 100, "High Load": 500}


def build_jmx(urls: list[str], users: int, ramp_s: int, duration_s: int, think_ms: int = 1000,
              assertion_ms: int = 3000) -> str:
    samplers = []
    for u in urls:
        p = urlparse(u)
        path = (p.path or "/") + (f"?{p.query}" if p.query else "")
        samplers.append(f"""
        <HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy" testname="{escape(path)}" enabled="true">
          <stringProp name="HTTPSampler.domain">{escape(p.hostname or '')}</stringProp>
          <stringProp name="HTTPSampler.port">{p.port or ''}</stringProp>
          <stringProp name="HTTPSampler.protocol">{p.scheme}</stringProp>
          <stringProp name="HTTPSampler.path">{escape(path)}</stringProp>
          <stringProp name="HTTPSampler.method">GET</stringProp>
          <boolProp name="HTTPSampler.follow_redirects">true</boolProp>
          <boolProp name="HTTPSampler.use_keepalive">true</boolProp>
        </HTTPSamplerProxy>
        <hashTree>
          <DurationAssertion guiclass="DurationAssertionGui" testclass="DurationAssertion" testname="Response time" enabled="true">
            <stringProp name="DurationAssertion.duration">{assertion_ms}</stringProp>
          </DurationAssertion>
          <hashTree/>
        </hashTree>""")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6">
  <hashTree>
    <TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="CreativeStall Audit Load Test" enabled="true"/>
    <hashTree>
      <ThreadGroup guiclass="ThreadGroupGui" testclass="ThreadGroup" testname="Users" enabled="true">
        <stringProp name="ThreadGroup.on_sample_error">continue</stringProp>
        <elementProp name="ThreadGroup.main_controller" elementType="LoopController" guiclass="LoopControlPanel" testclass="LoopController">
          <boolProp name="LoopController.continue_forever">false</boolProp>
          <intProp name="LoopController.loops">-1</intProp>
        </elementProp>
        <stringProp name="ThreadGroup.num_threads">{users}</stringProp>
        <stringProp name="ThreadGroup.ramp_time">{ramp_s}</stringProp>
        <boolProp name="ThreadGroup.scheduler">true</boolProp>
        <stringProp name="ThreadGroup.duration">{duration_s}</stringProp>
      </ThreadGroup>
      <hashTree>
        <ConstantTimer guiclass="ConstantTimerGui" testclass="ConstantTimer" testname="Think time" enabled="true">
          <stringProp name="ConstantTimer.delay">{think_ms}</stringProp>
        </ConstantTimer>
        <hashTree/>{''.join(samplers)}
      </hashTree>
    </hashTree>
  </hashTree>
</jmeterTestPlan>
"""


def parse_jtl(path: Path) -> dict[str, Any]:
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    if not rows:
        return {"samples": 0}
    elapsed = sorted(int(r["elapsed"]) for r in rows)
    errors = sum(1 for r in rows if r.get("success", "true").lower() != "true")
    ts = [int(r["timeStamp"]) for r in rows]
    span = max(1, (max(ts) - min(ts)) / 1000)

    def pct(p: float) -> int:
        return elapsed[min(len(elapsed) - 1, int(p * len(elapsed)))]

    per_label: dict[str, list[int]] = {}
    for r in rows:
        per_label.setdefault(r["label"], []).append(int(r["elapsed"]))
    return {
        "samples": len(rows), "errors": errors, "error_rate": round(100 * errors / len(rows), 2),
        "avg_ms": round(statistics.mean(elapsed), 1), "p50_ms": pct(0.5), "p90_ms": pct(0.9), "p95_ms": pct(0.95),
        "p99_ms": pct(0.99), "max_ms": elapsed[-1], "throughput_rps": round(len(rows) / span, 2),
        "per_label": {k: {"count": len(v), "avg_ms": round(statistics.mean(v), 1)} for k, v in per_label.items()},
    }


def run_jmeter(urls: list[str], users: int, ramp_s: int, duration_s: int, workdir: Path,
               cancel_check=lambda: False, max_error_rate_stop: float = 20.0) -> dict[str, Any]:
    exe = find_jmeter()
    if not exe:
        raise RuntimeError("Apache JMeter not found. Install Java 17+ and JMeter 5.6+, then set JMETER_HOME.")
    workdir.mkdir(parents=True, exist_ok=True)
    jmx = workdir / "plan.jmx"
    jtl = workdir / "results.jtl"
    jmx.write_text(build_jmx(urls, users, ramp_s, duration_s), encoding="utf-8")
    if jtl.exists():
        jtl.unlink()
    cmd = [exe, "-n", "-t", str(jmx), "-l", str(jtl), "-Jjmeter.save.saveservice.output_format=csv"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    import time
    deadline = time.monotonic() + duration_s + ramp_s + 120
    stopped_reason = ""
    while proc.poll() is None:
        time.sleep(2)
        if cancel_check():
            stopped_reason = "cancelled by user"
        elif time.monotonic() > deadline:
            stopped_reason = "timeout"
        elif jtl.exists():
            try:
                partial = parse_jtl(jtl)
                if partial.get("samples", 0) > 50 and partial["error_rate"] > max_error_rate_stop:
                    stopped_reason = f"emergency stop: error rate {partial['error_rate']}% > {max_error_rate_stop}%"
            except Exception:  # noqa: BLE001
                pass
        if stopped_reason:
            proc.terminate()
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
    result = parse_jtl(jtl) if jtl.exists() else {"samples": 0}
    result["stopped_reason"] = stopped_reason
    result["jmx_path"] = str(jmx)
    result["jtl_path"] = str(jtl)
    return result
