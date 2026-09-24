# 共用漏洞模式定义

`vulnerability-patterns.json` 是漏洞模式的唯一来源（single source of truth）：

- 后端 `backend/app/main.py` 启动时加载本文件，用于扫描（`detect_vulnerabilities`）和 `GET /api/patterns`。
- 前端 `frontend/src/views/PatternsView.vue` 直接导入本文件渲染漏洞模式库。

字段统一写法：`name` / `severity` / `regex` / `description` / `suggestion`。
数组顺序即前端展示顺序。修改模式时只需改这一份，两边同时生效，请勿在任一端再维护副本。
