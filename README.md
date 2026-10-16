# prj3-dataset

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
  "e_i": 8,
  "effort_points": 8,
  "t_i": 32.0,
  "skill": "SKILL_A07",
  "commit_timestamp": 1607354700.0,
  "sprint_discovered": 1,
  "earliest_sprint": 1,
  "deadline_sprint": 4,
  "predecessors": [],
  "fixing_info": {
    "commit_id": "1b74b12f5cab26118d47ece3e6766ffcf96fbec9",
    "parent_commit": "c06cba87caa6dba49a7d7f27738d4561b42660ec",
    "file_path": "ts-admin-basic-info-service/src/main/java/adminbasic/config/SecurityConfig.java",
    "lines_range": "58-60"
  }
}
```

| Field | Type | Description | Source / Rule |
|---|---|---|---|
| `id` | Integer | Unique finding ID. | [Raw Dataset](file:///home/kibito/Desktop/repos/project3/dataset/prj3-dataset-crawl/raw/combined_positive_gold_silver.jsonl) (`item["id"]`) |
| `title` | String | Technical rule identifier (`rule_id`). | [Raw Dataset](file:///home/kibito/Desktop/repos/project3/dataset/prj3-dataset-crawl/raw/combined_positive_gold_silver.jsonl) (`item["rule_id"]`), fallback "Security Issue" ([rules.py](file:///home/kibito/Desktop/repos/project3/dataset/prj3-dataset-crawl/src/rules.py)) |
| `cwe` | String | Common Weakness Enumeration ID. | [MITRE CWE List](https://cwe.mitre.org/data/definitions/1344.html) (`item["cwe"][0]`) |
| `repository` | String | Source code repository URL. | [Raw Dataset](file:///home/kibito/Desktop/repos/project3/dataset/prj3-dataset-crawl/raw/combined_positive_gold_silver.jsonl) (`item["repo"]`) |
| `asset_module` | String | Target module / microservice name. | Extracted from root folder of `item["file_path"]` ([parser.py](file:///home/kibito/Desktop/repos/project3/dataset/prj3-dataset-crawl/src/parser.py)) |
| `r_i` | Float | Risk score $[1.0, 10.0]$. | Mapped from [FIRST CVSS v3.1 Qualitative Scale](https://www.first.org/cvss/v3.1/specification-document#5-Qualitative-Severity-Rating-Scale) ([Sec 4.2](#42-risk-score-r_i)). |
| `e_i` | Integer | Estimated effort in Fibonacci Story Points $\{1, 2, 3, 5, 8\}$. | Linear-Log Multi-factor Model (SQALE IEEE 2012 / VULCON ACM TOPS 2018 / COCOMO II) ([Sec 4.3](#43-effort-e_i-and-duration-t_i)). |
| `t_i` | Float | Estimated duration in ideal hours ($t_i = e_i \times 4.0\text{h}$). | Agile Scrum standard: 1 SP = 4 ideal development hours. |
| `skill` | String | OWASP Top 10 remediation skill (`SKILL_A01` - `SKILL_A10`). | Mapped via [OWASP Top 10 (2021)](https://owasp.org/Top10/A00_2021_Introduction/) & [MITRE CWE-1344](https://cwe.mitre.org/data/definitions/1344.html) ([Sec 4.1](#41-owasp-skill-mapping-cwe---skill)). |
| `commit_timestamp`| Float | Unix timestamp of git commit. | Parsed from ISO `author_date` string in Git history. |
| `sprint_discovered` | Integer | Sprint index where issue was discovered ($1 \le s_{\text{disc}} \le K$). | Quantile Binning based on Git commit timeline ([Sec 4.4](#44-dynamic-sprints-k-discovery-timeline--sla-deadline)). |
| `earliest_sprint` | Integer | Earliest sprint allowed to start ($a_i = s_{\text{disc}}$). | Synced with sprint discovery and DAG dependencies. |
| `deadline_sprint` | Integer | Latest sprint required to complete ($b_i$). | PCI-DSS / CISA BOD SLA deadline + Backward DAG Monotonicity ($b_u \le b_v$) ([Sec 4.4](#44-dynamic-sprints-k-discovery-timeline--sla-deadline)). |
| `predecessors` | Array[Integer] | Prerequisite task IDs (must finish before $v_i$). | Intra-service precedence: security config before controller logic ([Sec 4.5](#45-precedence-generation-intra-service-architecture-rule)). |
| `fixing_info` | Object | Commit hash, file path, line range. | [Raw Dataset](file:///home/kibito/Desktop/repos/project3/dataset/prj3-dataset-crawl/raw/combined_positive_gold_silver.jsonl) (`commit_id`, `parent_commit`, `file_path`, `s_line`, `e_line`). |

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

Remediation effort is estimated using the **Multi-factor Linear-Log with Offset Model** grounded in SQALE (IEEE 2012), VULCON (ACM TOPS 2018), and COCOMO II:

$$H_i = \left[ H_{\text{base}}(\text{cwe}_i, \text{title}_i) + 0.5 \cdot \ln(1 + \text{span}_i) \right] \times M_{\text{arch}}(\text{file\_path}_i)$$

1. **Base Effort ($H_{\text{base}}$)**:
   - *Tier 1: Trivial / Literal / Config* ($1.0\text{h}$): `CWE-798`, `CWE-259`, `CWE-330`, `CWE-532`, logger leak, weak cipher/hash.
   - *Tier 2: Medium / Sanitization* ($2.5\text{h}$ - Default): `CWE-89`, `CWE-79`, `CWE-22`, `CWE-611`, `CWE-78` (SQLi, XSS, Path Traversal).
   - *Tier 3: Major / Build Upgrade* ($4.5\text{h}$): `CWE-937`, `pom.xml`, `build.gradle`, dependency version conflicts.
   - *Tier 4: High / Architecture Control* ($7.0\text{h}$): `CWE-352`, `CWE-284`, `CWE-287`, `CWE-862` (CSRF, AuthN/AuthZ, JWT).

2. **Architectural Multiplier ($M_{\text{arch}}$)**:
   - *Isolated / Leaf* ($1.0\times$): `*DTO.java`, `*Entity.java`, `*Model.java`, `*Util.java`.
   - *Business / Endpoint* ($1.3\times$): `*Controller.java`, `*Service.java`, `*Repository.java`.
   - *Core Config / Cross-Cutting* ($1.6\times$): `*Config.java`, `*Security.java`, `*Filter.java`, `pom.xml`.

3. **Fibonacci Story Point Quantization ($e_i \in \{1, 2, 3, 5, 8\}$)**:
   - $H_i \le 2.0\text{h} \implies 1\text{ SP}$
   - $2.0\text{h} < H_i \le 4.0\text{h} \implies 2\text{ SP}$
   - $4.0\text{h} < H_i \le 7.0\text{h} \implies 3\text{ SP}$
   - $7.0\text{h} < H_i \le 11.0\text{h} \implies 5\text{ SP}$
   - $H_i > 11.0\text{h} \implies 8\text{ SP}$
   - Duration in ideal hours: $t_i = e_i \times 4.0\text{h}$.

### 4.4. Dynamic Sprints ($K$), Discovery Timeline & SLA Deadline

1. **Dynamic Sprint Count ($K$)**:
   - Total backlog effort: $E_{\text{total}} = \sum e_i = 6,752\text{ SP}$.
   - System sprint capacity: $C_{\text{total}} = \sum \text{cap}_t \approx 80\text{ SP/sprint}$.
   - Optimal release horizon: $K = 8\text{ Sprints}$.

2. **Quantile Binning Timeline ($s_{\text{disc}}$)**:
   - Sorted by Git commit timestamp `commit_timestamp` into $K=8$ equal quantiles: $1 \le s_{\text{disc}} \le 8$.
   - Forward DAG Sync: If $u \in \text{predecessors}(v)$, then $s_{\text{disc}}(u) \le s_{\text{disc}}(v)$.

3. **International SLA Deadline ($b_i$)**:
   - Aligned with PCI-DSS Req 6.2 and CISA BOD 22-01:
     - Critical ($r_i \ge 9.0$): $b_i = s_{\text{disc}} + 1$
     - High ($7.0 \le r_i < 9.0$): $b_i = s_{\text{disc}} + 2$
     - Medium ($4.0 \le r_i < 7.0$): $b_i = s_{\text{disc}} + 3$
     - Low ($r_i < 4.0$): $b_i = \min(s_{\text{disc}} + 4, K)$
   - **Backward DAG Monotonicity**: For each dependency edge $u \in \text{predecessors}(v)$, enforce $b_u \leftarrow \min(b_u, b_v)$ ensuring $b_u \le b_v$.

### 4.5. Precedence Generation (Intra-Service Architecture Rule)

Dependencies strictly apply within the same service/module ($\forall u \in predecessors(v) \implies asset\_module(u) = asset\_module(v)$):

* **Config before Logic:** Security configurations (`SecurityConfig`, `WebSecurityConfig`, `AuthConfig`) must be remediated prior to API endpoints (`Controller`) in the same microservice.
* Cross-service dependencies are not coupled in sprint backlogs because microservices are developed and remediated independently by distinct teams using mocks and API contracts.
