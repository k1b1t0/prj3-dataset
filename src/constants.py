# 1. owasp top 10 mapping: https://owasp.org/Top10/A00_2021_Introduction/
# 2. mitre cwe-1344 mapping: https://cwe.mitre.org/data/definitions/1344.html
CWE_TO_OWASP = {
    # A01: Broken Access Control
    "CWE-22": "SKILL_A01", "CWE-284": "SKILL_A01", "CWE-862": "SKILL_A01",
    "CWE-863": "SKILL_A01", "CWE-732": "SKILL_A01", "CWE-264": "SKILL_A01",
    # A02: Cryptographic Failures
    "CWE-310": "SKILL_A02", "CWE-326": "SKILL_A02", "CWE-327": "SKILL_A02",
    "CWE-330": "SKILL_A02", "CWE-338": "SKILL_A02", "CWE-315": "SKILL_A02",
    # A03: Injection
    "CWE-77": "SKILL_A03", "CWE-78": "SKILL_A03", "CWE-79": "SKILL_A03",
    "CWE-89": "SKILL_A03", "CWE-91": "SKILL_A03", "CWE-74": "SKILL_A03",
    # A04: Insecure Design
    "CWE-209": "SKILL_A04", "CWE-215": "SKILL_A04", "CWE-362": "SKILL_A04", "CWE-489": "SKILL_A04",
    # A05: Security Misconfiguration
    "CWE-16": "SKILL_A05", "CWE-552": "SKILL_A05", "CWE-611": "SKILL_A05", "CWE-1188": "SKILL_A05",
    # A06: Vulnerable and Outdated Components
    "CWE-1104": "SKILL_A06",
    # A07: Identification and Authentication Failures
    "CWE-287": "SKILL_A07", "CWE-352": "SKILL_A07", "CWE-384": "SKILL_A07",
    "CWE-614": "SKILL_A07", "CWE-1004": "SKILL_A07", "CWE-640": "SKILL_A07", "CWE-798": "SKILL_A07",
    # A08: Software and Data Integrity Failures
    "CWE-494": "SKILL_A08", "CWE-502": "SKILL_A08", "CWE-915": "SKILL_A08", "CWE-346": "SKILL_A08",
    # A09: Security Logging and Monitoring Failures
    "CWE-200": "SKILL_A09", "CWE-532": "SKILL_A09", "CWE-212": "SKILL_A09",
    # A10: Server-Side Request Forgery
    "CWE-918": "SKILL_A10", "CWE-295": "SKILL_A10", "CWE-942": "SKILL_A10"
}

# https://www.first.org/cvss/v3.1/specification-document#5-Qualitative-Severity-Rating-Scale
SEVERITY_TO_RISK = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "WARNING": 6.5,
    "MEDIUM": 6.0,
    "LOW": 3.0,
    "INFO": 1.5
}
