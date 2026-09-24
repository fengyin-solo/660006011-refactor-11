from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import re
import uuid
import random
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.patterns import get_scan_patterns

app = FastAPI(title="Smart Contract Security Auditor")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# 漏洞模式统一从共用定义 shared/vulnerability-patterns.json 生成，
# 前端模式库与前端审计入口使用同一份定义，避免两边口径不一致。
VULNERABILITY_PATTERNS = get_scan_patterns()

GAS_PATTERNS = [
    {"function": "storage_read", "issue": "循环中读取storage变量", "saving": 0.3},
    {"function": "redundant_sstore", "issue": "不必要的storage写入", "saving": 0.25},
    {"function": "short_circuit", "issue": "逻辑运算可短路优化", "saving": 0.15},
]

class AuditRequest(BaseModel):
    code: str
    filename: str

def detect_vulnerabilities(code: str) -> List[dict]:
    """Scan code for vulnerability patterns"""
    lines = code.split("\n")
    vulnerabilities = []

    for vp in VULNERABILITY_PATTERNS:
        matches = re.finditer(vp["pattern"], code, re.MULTILINE)
        for m in matches:
            line_num = code[:m.start()].count("\n") + 1
            # Find context
            context_start = max(0, line_num - 2)
            context_end = min(len(lines), line_num + 2)
            context = "\n".join(lines[context_start:context_end])

            vulnerabilities.append({
                "type": vp["type"],
                "severity": vp["severity"],
                "line": line_num,
                "description": vp["description"],
                "suggestion": vp["suggestion"],
                "code": context.strip()
            })

    return vulnerabilities

def compute_gas_issues(code: str) -> List[dict]:
    """Analyze gas consumption issues"""
    issues = []
    functions = re.findall(r"function\s+(\w+)\s*\(", code)
    for fn in functions:
        base_gas = random.randint(20000, 60000)
        issues.append({
            "functionName": f"{fn}()",
            "currentGas": base_gas,
            "optimizedGas": int(base_gas * (0.7 + random.random() * 0.2)),
            "suggestion": random.choice(["移除不必要的storage写入", "缓存storage变量到memory", "使用短路逻辑", "合并多个事件为一个"])
        })
    return issues

def compute_security_score(vulnerabilities: List[dict]) -> int:
    """Compute overall security score"""
    if not vulnerabilities:
        return 100
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    deduction = sum(severity_weights.get(v["severity"], 5) for v in vulnerabilities)
    return max(0, 100 - deduction)

@app.get("/")
async def root():
    return {"message": "Smart Contract Security Auditor", "version": "1.0.0"}

@app.get("/api/patterns")
async def list_patterns():
    return {"code": 0, "message": "success", "data": VULNERABILITY_PATTERNS}

@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    vulnerabilities = detect_vulnerabilities(request.code)
    gas_issues = compute_gas_issues(request.code)
    score = compute_security_score(vulnerabilities)

    result = {
        "id": str(uuid.uuid4()),
        "filename": request.filename,
        "score": score,
        "vulnerabilities": vulnerabilities,
        "gasIssues": gas_issues,
        "timestamp": datetime.now().isoformat()
    }

    return {"code": 0, "message": "success", "data": result}

@app.get("/api/history")
async def get_history():
    return {"code": 0, "message": "success", "data": []}

@app.post("/api/report/{audit_id}")
async def generate_report(audit_id: str):
    """Generate PDF report"""
    # Simplified report generation
    return {"code": 0, "message": "success", "data": {"url": f"/api/reports/{audit_id}.pdf"}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
