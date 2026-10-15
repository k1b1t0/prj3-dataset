import math
from constants import CWE_TO_OWASP, SEVERITY_TO_RISK


def get_skill(cwe_list: list) -> str:
    # lay 1 skill duy nhat theo cwe dau tien
    if not cwe_list:
        return "SKILL_A05"
    return CWE_TO_OWASP.get(cwe_list[0], "SKILL_A05")


def get_risk(severity: str, file_path: str = "") -> float:
    # lay diem risk chuan theo bang cvss v3.1 qualitative scale
    return float(SEVERITY_TO_RISK.get(severity, 5.0))


def get_base_hours(cwe: str, title: str, file_path: str = "") -> float:
    """
    Xac dinh gio cong co so H_base dua tren ban chat ky thuat (SQALE IEEE 2012 / VULCON ACM TOPS 2018).
    """
    cwe_upper = (cwe or "").upper()
    title_lower = (title or "").lower()
    path_lower = (file_path or "").lower()

    # Tier 4: Architectural & Core Control (7.0h)
    tier4_cwes = {"CWE-352", "CWE-284", "CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-502", "CWE-362"}
    if any(c in cwe_upper for c in tier4_cwes) or any(k in title_lower for k in ["csrf", "deserializ", "race_condition", "auth_bypass", "broken_auth"]):
        return 7.0

    # Tier 3: Dependency & Build Upgrade (4.5h)
    tier3_cwes = {"CWE-937", "CWE-1035", "CWE-1104"}
    if (any(c in cwe_upper for c in tier3_cwes) or 
            path_lower.endswith("pom.xml") or 
            path_lower.endswith("build.gradle") or 
            any(k in title_lower for k in ["dependency", "outdated", "version", "vulnerable_dep"])):
        return 4.5

    # Tier 1: Trivial / Easy (Local Literal & Config) (1.0h)
    tier1_cwes = {"CWE-798", "CWE-259", "CWE-330", "CWE-338", "CWE-327", "CWE-328", "CWE-614", "CWE-1004", "CWE-532", "CWE-209", "CWE-215", "CWE-489"}
    if any(c in cwe_upper for c in tier1_cwes) or any(k in title_lower for k in ["logger_leak", "information_leak", "hardcoded", "cookie", "random", "weak_cipher", "weak_hash", "empty_catch", "debug_info"]):
        return 1.0

    # Tier 2: Medium (Data-flow & Sanitization) - Default fallback (2.5h)
    return 2.5


def get_arch_multiplier(file_path: str) -> float:
    """
    He so nhan kien truc M_arch(file_path) theo ly thuyet Software Change Impact Analysis (Bohner & Arnold 1996)
    va Effort Multipliers cua COCOMO II.
    """
    if not file_path:
        return 1.0
    p = file_path.lower()

    # Core Config / Cross-Cutting (1.6)
    if any(k in p for k in ["securityconfig", "websecurity", "authconfig", "filter", "gateway", "pom.xml", "build.gradle", "application.yml", "application.properties", "config.java"]):
        return 1.6

    # Business / Endpoint (1.3)
    if any(k in p for k in ["controller", "service", "repository", "dao", "client"]):
        return 1.3

    # Isolated / Leaf (1.0)
    if any(k in p for k in ["dto", "vo", "entity", "model", "util", "constant", "exception"]):
        return 1.0

    return 1.15


def get_effort(cwe: str = "", title: str = "", file_path: str = "", s_line: int = None, e_line: int = None, **kwargs) -> int:
    """
    Tinh no luc va loi e_i thuoc {1, 2, 3, 5, 8} theo mo hinh Linear-Log with Offset:
    H_i = [H_base(cwe, title) + 0.5 * ln(1 + span)] * M_arch(file_path)
    Anh xa Fibonacci:
      <= 2.0h -> 1 SP
      <= 4.0h -> 2 SP
      <= 7.0h -> 3 SP
      <= 11.0h -> 5 SP
      > 11.0h  -> 8 SP
    """
    # Ho tro ca goi kieu cu get_effort(s_line, e_line)
    if isinstance(cwe, int) and isinstance(title, int) and s_line is None and e_line is None:
        s_line, e_line = cwe, title
        cwe = ""
        title = ""

    span = 1
    if s_line is not None and e_line is not None:
        span = max(1, abs(e_line - s_line) + 1)

    h_base = get_base_hours(cwe, title, file_path)
    m_arch = get_arch_multiplier(file_path)

    h_i = (h_base + 0.5 * math.log(1.0 + span)) * m_arch

    if h_i <= 2.0:
        return 1
    elif h_i <= 4.0:
        return 2
    elif h_i <= 7.0:
        return 3
    elif h_i <= 11.0:
        return 5
    else:
        return 8


def get_deadline(r_i: float, sprint_discovered: int = 1, max_sprints: int = 8) -> int:
    """
    Deadline theo chuan SLA bao mat quoc te (PCI-DSS / CISA BOD):
      r_i >= 9.0 -> s_disc + 1
      7.0 <= r_i < 9.0 -> s_disc + 2
      4.0 <= r_i < 7.0 -> s_disc + 3
      r_i < 4.0 -> min(s_disc + 4, max_sprints)
    """
    if r_i >= 9.0:
        delta = 1
    elif r_i >= 7.0:
        delta = 2
    elif r_i >= 4.0:
        delta = 3
    else:
        delta = 4
    return min(sprint_discovered + delta, max_sprints)


def make_title(rule_id: str) -> str:
    # dung luon ma rule co san lam title
    return rule_id if rule_id else "Security Issue"
