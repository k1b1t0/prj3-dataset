from src.constants import CWE_TO_OWASP, SEVERITY_TO_RISK


def get_skill(cwe_list: list) -> str:
    # lay 1 skill duy nhat theo cwe dau tien
    if not cwe_list:
        return "SKILL_A05"
    return CWE_TO_OWASP.get(cwe_list[0], "SKILL_A05")


def get_risk(severity: str, file_path: str) -> float:
    # lay diem risk tu severity, tinh chinh theo tinh chat file
    r = SEVERITY_TO_RISK.get(severity, 5.0)
    if "SecurityConfig" in file_path:
        r = min(10.0, r + 1.0)
    elif "CookieUtil" in file_path:
        r = max(1.0, r - 0.5)
    return round(r, 1)


def get_effort(s_line: int, e_line: int) -> int:
    # tinh effort theo do rong dong code loi
    if s_line is None or e_line is None:
        return 2
    span = abs(e_line - s_line) + 1
    if span <= 3:
        return 2
    elif span <= 15:
        return 3
    return 5


def get_deadline(r_i: float) -> int:
    # deadline nghich bien voi risk
    if r_i >= 8.5:
        return 1
    elif r_i >= 7.0:
        return 2
    elif r_i >= 4.0:
        return 3
    return 4


def make_title(rule_id: str) -> str:
    # dung luon ma rule co san lam title
    return rule_id if rule_id else "Security Issue"
