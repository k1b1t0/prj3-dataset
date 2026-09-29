# dataset-prj3

Dataset generation benchmark for Project 3

---

## 1. Directory Structure

```
dataset-prj3/
├── pyproject.toml
├── README.md
├── raw/
│   ├── train_ticket_positive_gold.jsonl
│   └── vcc_eval_100.json
├── src/
│   ├── constants.py
│   ├── rules.py
│   ├── parser.py
│   └── mock_generator.py
├── target/
│   ├── vulnerabilities_backlog.jsonl
│   ├── teams.jsonl
│   └── sprints.jsonl
└── main.py
```

---

## 2. Quick Start

Install dependencies and generate the dataset using `uv`:

```bash
cd dataset-prj3
uv sync
uv run main.py
```

Output files are generated in `dataset-prj3/target/`.

---

## 3. Schema Specification (JSONL Format)

### 3.1. Vulnerabilities ($v_i \in V$) — `target/vulnerabilities_backlog.jsonl`

```json
{
  "id": 34897,
  "title": "java.spring.security.audit.spring-csrf-disabled.spring-csrf-disabled",
  "cwe": "CWE-352",
  "repository": "https://github.com/FudanSELab/train-ticket",
  "asset_module": "ts-admin-basic-info-service",
  "r_i": 7.5,
  "e_i": 2,
  "t_i": 8.0,
  "skill": "SKILL_A07",
  "earliest_sprint": 1,
  "deadline_sprint": 2,
  "predecessors": [],
  "fixing_info": {
    "commit_id": "1b74b12f5cab26118d47ece3e6766ffcf96fbec9",
    "file_path": "ts-admin-basic-info-service/src/main/java/adminbasic/config/SecurityConfig.java",
    "lines_range": "58-60"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `id` | Integer | Unique finding ID from raw dataset. |
| `title` | String | Technical rule identifier (`rule_id`). |
| `cwe` | String | Common Weakness Enumeration ID. |
| `repository` | String | Source code repository URL. |
| `asset_module` | String | System asset / Microservice name. |
| `r_i` | Float | Risk score $[1.0, 10.0]$. |
| `e_i` | Integer | Estimated effort in Story Points. |
| `t_i` | Float | Estimated duration in hours ($t_i = e_i \times 4.0$). |
| `skill` | String | OWASP Top 10 remediation skill (`SKILL_A01` - `SKILL_A10`). |
| `earliest_sprint` | Integer | Earliest sprint allowed to start ($a_i = 1$). |
| `deadline_sprint` | Integer | Latest sprint required to complete ($b_i$). |
| `predecessors` | Array[String] | Prerequisite task IDs (must finish before $v_i$). |
| `fixing_info` | Object | Commit hash, file path, and line range. |

### 3.2. Teams ($t \in T$) — `target/teams.jsonl`

```json
{"team_id": "team_auth_core", "name": "Authentication & Core Services Team", "capacity_sp": 25, "skills": {"SKILL_A01": 0.9, "SKILL_A02": 0.5, "SKILL_A03": 0.5, "SKILL_A04": 0.7, "SKILL_A05": 0.6, "SKILL_A06": 0.4, "SKILL_A07": 0.95, "SKILL_A08": 0.6, "SKILL_A09": 0.5, "SKILL_A10": 0.4}}
{"team_id": "team_business_payment", "name": "Payment & Order Business Team", "capacity_sp": 30, "skills": {"SKILL_A01": 0.6, "SKILL_A02": 0.8, "SKILL_A03": 0.9, "SKILL_A04": 0.85, "SKILL_A05": 0.5, "SKILL_A06": 0.5, "SKILL_A07": 0.6, "SKILL_A08": 0.8, "SKILL_A09": 0.5, "SKILL_A10": 0.5}}
{"team_id": "team_infra_gateway", "name": "Gateway & Security Infrastructure Team", "capacity_sp": 25, "skills": {"SKILL_A01": 0.7, "SKILL_A02": 0.5, "SKILL_A03": 0.6, "SKILL_A04": 0.5, "SKILL_A05": 0.95, "SKILL_A06": 0.7, "SKILL_A07": 0.5, "SKILL_A08": 0.6, "SKILL_A09": 0.8, "SKILL_A10": 0.9}}
```

| Field | Type | Description |
|---|---|---|
| `team_id` | String | Unique team identifier. |
| `name` | String | Team name / Domain responsibility. |
| `capacity_sp` | Integer | Max workload in Story Points per sprint ($cap_t$). |
| `skills` | Object | Skill level vector $k_{t, skill} \in [0.0, 1.0]$ for OWASP skills. |

* Team match score: $skill(t, v_i) = k_{t, skill_i}$.

### 3.3. Sprints ($s \in S$) — `target/sprints.jsonl`

```json
{"sprint_id": 1, "name": "Sprint 1", "budget_sp": 40}
{"sprint_id": 2, "name": "Sprint 2", "budget_sp": 40}
{"sprint_id": 3, "name": "Sprint 3", "budget_sp": 40}
{"sprint_id": 4, "name": "Sprint 4", "budget_sp": 40}
```

| Field | Type | Description |
|---|---|---|
| `sprint_id` | Integer | Sequential sprint index ($1, \dots, p$). |
| `name` | String | Sprint label. |
| `budget_sp` | Integer | Total story points capacity budget for sprint ($B_s$). |

---

## 4. Rule-Based Transformation

### 4.1. OWASP Skill Mapping (`CWE -> Skill`)

Mapped via OWASP Top 10 (2021) and MITRE CWE-1344:

| Skill | OWASP Category | Sample CWEs |
|---|---|---|
| `SKILL_A01` | Broken Access Control | CWE-22, CWE-284, CWE-862, CWE-863 |
| `SKILL_A02` | Cryptographic Failures | CWE-310, CWE-326, CWE-327, CWE-330 |
| `SKILL_A03` | Injection | CWE-77, CWE-78, CWE-79, CWE-89 |
| `SKILL_A04` | Insecure Design | CWE-209, CWE-215, CWE-362, CWE-489 |
| `SKILL_A05` | Security Misconfiguration | CWE-16, CWE-552, CWE-611, CWE-1188 |
| `SKILL_A06` | Vulnerable Components | CWE-1104 |
| `SKILL_A07` | Auth & Identification | CWE-287, CWE-352, CWE-614, CWE-1004 |
| `SKILL_A08` | Software/Data Integrity | CWE-494, CWE-502, CWE-915 |
| `SKILL_A09` | Logging & Monitoring | CWE-200, CWE-532 |
| `SKILL_A10` | SSRF & Network | CWE-918, CWE-295 |

### 4.2. Risk Score ($r_i$)

Derived from FIRST CVSS v3.1 Qualitative Rating:

| Severity | Base Risk | Contextual File Adjustment | Final $r_i$ |
|---|---|---|---|
| `CRITICAL` | 9.5 | None | 9.5 |
| `HIGH` | 8.0 | None | 8.0 |
| `WARNING` | 6.5 | `SecurityConfig` (+1.0) / `CookieUtil` (-0.5) | 7.5 / 6.0 |
| `MEDIUM` | 6.0 | `SecurityConfig` (+1.0) / `CookieUtil` (-0.5) | 7.0 / 5.5 |
| `LOW` | 3.0 | None | 3.0 |
| `INFO` | 1.5 | None | 1.5 |

### 4.3. Effort ($e_i$) and Duration ($t_i$)

Calculated from vulnerability line span (`e_line - s_line + 1`):

| Line Span | Effort ($e_i$) | Duration ($t_i = e_i \times 4.0\text{h}$) |
|---|---|---|
| $\le 3$ lines | 2 SP | 8.0 hours |
| $4 - 15$ lines | 3 SP | 12.0 hours |
| $> 15$ lines | 5 SP | 20.0 hours |

### 4.4. Deadline ($b_i$) & Backward Propagation

Initial mapping based on 4-sprint test scope:

| Risk Score ($r_i$) | Preliminary Deadline ($b_i$) |
|---|---|
| $r_i \ge 8.5$ | Sprint 1 |
| $7.0 \le r_i < 8.5$ | Sprint 2 |
| $4.0 \le r_i < 7.0$ | Sprint 3 |
| $r_i < 4.0$ | Sprint 4 |

**Backward DAG Sync:** For each $u \in predecessors(v)$, enforce $b_u \leftarrow \min(b_u, b_v)$ to prevent infeasible schedules.

### 4.5. Precedence Generation (Dataset-Specific Conventions)

Conventions tailored for the `train-ticket` microservices benchmark:
1. **Config before Logic (Intra-Service):** If a service contains a `SecurityConfig` flaw and a `Controller` flaw, `SecurityConfig` must be remediated first.
2. **Auth Service Call Graph (Inter-Service):** Vulnerabilities in `ts-auth-service` are prerequisites for downstream user/payment services (`ts-user-service`, `ts-inside-payment-service`).
