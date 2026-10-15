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
│   ├── vcc_eval_100.json
│   └── combined_positive_gold_silver.jsonl
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

Output files are generated under `target/`.

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
  "r_i": 6.5,
  "e_i": 2,
  "t_i": 8.0,
  "skill": "SKILL_A07",
  "earliest_sprint": 1,
  "deadline_sprint": 3,
  "predecessors": [],
  "fixing_info": {
    "commit_id": "1b74b12f5cab26118d47ece3e6766ffcf96fbec9",
    "file_path": "ts-admin-basic-info-service/src/main/java/adminbasic/config/SecurityConfig.java",
    "lines_range": "58-60"
  }
}
```

| Field | Type | Description | Source / Rule |
|---|---|---|---|
| `id` | Integer | Unique finding ID. | [Raw Dataset](file:///home/kibito/Desktop/repos/project3/prj3-dataset-crawl/raw/combined_positive_gold_silver.jsonl) (`item["id"]`) |
| `title` | String | Technical rule identifier (`rule_id`). | [Raw Dataset](file:///home/kibito/Desktop/repos/project3/prj3-dataset-crawl/raw/combined_positive_gold_silver.jsonl) (`item["rule_id"]`), fallback "Security Issue" ([rules.py](file:///home/kibito/Desktop/repos/project3/prj3-dataset-crawl/src/rules.py)) |
| `cwe` | String | Common Weakness Enumeration ID. | [MITRE CWE List](https://cwe.mitre.org/data/definitions/1344.html) (`item["cwe"][0]`) |
| `repository` | String | Source code repository URL. | [Raw Dataset](file:///home/kibito/Desktop/repos/project3/prj3-dataset-crawl/raw/combined_positive_gold_silver.jsonl) (`item["repo"]`) |
| `asset_module` | String | Target module / microservice name. | Extracted from root folder of `item["file_path"]` ([parser.py](file:///home/kibito/Desktop/repos/project3/prj3-dataset-crawl/src/parser.py)) |
| `r_i` | Float | Risk score $[1.0, 10.0]$. | Mapped from [FIRST CVSS v3.1 Qualitative Scale](https://www.first.org/cvss/v3.1/specification-document#5-Qualitative-Severity-Rating-Scale) ([Sec 4.2](#42-risk-score-r_i)). |
| `e_i` | Integer | Estimated effort in Story Points. | Line span rule ($e\_line - s\_line + 1$) ([Sec 4.3](#43-effort-e_i-and-duration-t_i)). |
| `t_i` | Float | Estimated duration in hours ($t_i = e_i \times 4.0$). | Agile standard: $t_i = e_i \times 4.0\text{h}$ (1 SP = 4 hours). |
| `skill` | String | OWASP Top 10 remediation skill (`SKILL_A01` - `SKILL_A10`). | Mapped via [OWASP Top 10 (2021)](https://owasp.org/Top10/A00_2021_Introduction/) & [MITRE CWE-1344](https://cwe.mitre.org/data/definitions/1344.html) ([Sec 4.1](#41-owasp-skill-mapping-cwe---skill)). |
| `earliest_sprint` | Integer | Earliest sprint allowed to start ($a_i = 1$). | Initialized to 1 (all tasks ready unless constrained by predecessors). |
| `deadline_sprint` | Integer | Latest sprint required to complete ($b_i$). | Inverse to $r_i$ + backward DAG propagation ($b_{pred} \le b_{succ}$) ([Sec 4.4](#44-deadline-b_i--backward-propagation)). |
| `predecessors` | Array[Integer] | Prerequisite task IDs (must finish before $v_i$). | Intra-service precedence: security config before controller logic ([Sec 4.5](#45-precedence-generation-intra-service-architecture-rule)). |
| `fixing_info` | Object | Commit hash, file path, line range. | [Raw Dataset](file:///home/kibito/Desktop/repos/project3/prj3-dataset-crawl/raw/combined_positive_gold_silver.jsonl) (`commit_id`, `parent_commit`, `file_path`, `s_line`, `e_line`). |

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

Mapped via [OWASP Top 10 (2021)](https://owasp.org/Top10/A00_2021_Introduction/) and [MITRE CWE-1344](https://cwe.mitre.org/data/definitions/1344.html):

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

Directly mapped from the [FIRST CVSS v3.1 Qualitative Severity Rating Scale](https://www.first.org/cvss/v3.1/specification-document#5-Qualitative-Severity-Rating-Scale):

| Severity | Risk Score ($r_i$) |
|---|:---:|
| `CRITICAL` | 9.5 |
| `HIGH` | 8.0 |
| `WARNING` | 6.5 |
| `MEDIUM` | 6.0 |
| `LOW` | 3.0 |
| `INFO` | 1.5 |

### 4.3. Effort ($e_i$) and Duration ($t_i$)

Calculated from vulnerability line span (`e_line - s_line + 1`):

| Line Span | Effort ($e_i$) | Duration ($t_i = e_i \times 4.0\text{h}$) |
|---|---|---|
| $\le 3$ lines | 2 SP | 8.0 hours |
| $4 - 15$ lines | 3 SP | 12.0 hours |
| $> 15$ lines | 5 SP | 20.0 hours |

### 4.4. Deadline ($b_i$) & Backward Propagation

Initial mapping inversely proportional to risk score $r_i$:

| Risk Score ($r_i$) | Preliminary Deadline ($b_i$) |
|---|---|
| $r_i \ge 8.5$ | Sprint 1 |
| $7.0 \le r_i < 8.5$ | Sprint 2 |
| $4.0 \le r_i < 7.0$ | Sprint 3 |
| $r_i < 4.0$ | Sprint 4 |

**Backward DAG Sync:** For each dependency edge $u \in predecessors(v)$, enforce $b_u \leftarrow \min(b_u, b_v)$ to guarantee feasible scheduling.

### 4.5. Precedence Generation (Intra-Service Architecture Rule)

Dependencies strictly apply within the same service/module ($\forall u \in predecessors(v) \implies asset\_module(u) = asset\_module(v)$):

* **Config before Logic:** Security configurations (`SecurityConfig`, `WebSecurityConfig`, `AuthConfig`) must be remediated prior to API endpoints (`Controller`) in the same microservice.
* Cross-service dependencies are not coupled in sprint backlogs because microservices are developed and remediated independently by distinct teams using mocks and API contracts.
