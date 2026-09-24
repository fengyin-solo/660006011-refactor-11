"""漏洞模式共用定义。

唯一事实源位于仓库根目录的 shared/vulnerability-patterns.json，
前端模式库与前端审计入口同样从该文件生成，改动只需改这一处。
"""
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

_SHARED_DEFINITION = (
    Path(__file__).resolve().parents[2] / "shared" / "vulnerability-patterns.json"
)


@lru_cache(maxsize=1)
def load_pattern_definitions() -> List[Dict[str, Any]]:
    """从共用定义文件读取漏洞模式，保持文件中的展示顺序。"""
    with _SHARED_DEFINITION.open(encoding="utf-8") as f:
        data = json.load(f)
    return data["patterns"]


def get_scan_patterns() -> List[Dict[str, str]]:
    """供扫描与 /api/patterns 使用的视图，字段与历史输出保持一致。"""
    return [
        {
            "type": p["type"],
            "severity": p["severity"],
            "pattern": p["regex"],
            "description": p["findingDescription"],
            "suggestion": p["suggestion"],
        }
        for p in load_pattern_definitions()
    ]


@lru_cache(maxsize=1)
def _type_index() -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for p in load_pattern_definitions():
        index[p["type"]] = p
        for alias in p.get("aliases", []):
            index.setdefault(alias, p)
    return index


def resolve_pattern(type_name: Optional[str]) -> Optional[Dict[str, Any]]:
    """按扫描结论里记录的类型名（含历史别名）解析回当前定义。"""
    if not type_name:
        return None
    return _type_index().get(type_name)
