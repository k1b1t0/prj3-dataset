import math
from typing import List, Dict, Any


def build_teams() -> list:
    # tao danh sach doi nhom mau
    return [
        {
            "team_id": "team_auth_core",
            "name": "Authentication & Core Services Team",
            "capacity_sp": 25,
            "skills": {
                "SKILL_A01": 0.9, "SKILL_A02": 0.5, "SKILL_A03": 0.5, "SKILL_A04": 0.7,
                "SKILL_A05": 0.6, "SKILL_A06": 0.4, "SKILL_A07": 0.95, "SKILL_A08": 0.6,
                "SKILL_A09": 0.5, "SKILL_A10": 0.4
            }
        },
        {
            "team_id": "team_business_payment",
            "name": "Payment & Order Business Team",
            "capacity_sp": 30,
            "skills": {
                "SKILL_A01": 0.6, "SKILL_A02": 0.8, "SKILL_A03": 0.9, "SKILL_A04": 0.85,
                "SKILL_A05": 0.5, "SKILL_A06": 0.5, "SKILL_A07": 0.6, "SKILL_A08": 0.8,
                "SKILL_A09": 0.5, "SKILL_A10": 0.5
            }
        },
        {
            "team_id": "team_infra_gateway",
            "name": "Gateway & Security Infrastructure Team",
            "capacity_sp": 25,
            "skills": {
                "SKILL_A01": 0.7, "SKILL_A02": 0.5, "SKILL_A03": 0.6, "SKILL_A04": 0.5,
                "SKILL_A05": 0.95, "SKILL_A06": 0.7, "SKILL_A07": 0.5, "SKILL_A08": 0.6,
                "SKILL_A09": 0.8, "SKILL_A10": 0.9
            }
        }
    ]


def calculate_optimal_sprints(total_effort: int, team_capacity_per_sprint: int = 80, min_k: int = 6, max_k: int = 8) -> int:
    """
    Uoc tinh so Sprint dong K theo huong dan overall-plan.md va assign-sprint-plan.md:
    K = ceil(E_total / C_total) + 1, gioi han trong khoang [6, 8] cho release horizon.
    """
    if team_capacity_per_sprint <= 0:
        return max_k
    k_raw = math.ceil(total_effort / (team_capacity_per_sprint * 10)) + 1
    return max(min_k, min(max_k, k_raw if k_raw >= min_k else max_k))


def build_sprints(num_sprints: int = 8, budget_sp: int = 80) -> list:
    """
    Tao danh sach K sprints voi budget tuong ung voi tong nang luc he thong
    """
    return [
        {"sprint_id": i + 1, "name": f"Sprint {i + 1}", "budget_sp": budget_sp}
        for i in range(num_sprints)
    ]


def assign_sprint_timeline_and_sla(vulnerabilities: List[Dict[str, Any]], num_sprints: int = 8) -> List[Dict[str, Any]]:
    """
    Giai doan 2:
    1. Phan vi thoi gian (Quantile Binning) theo commit_timestamp -> sprint_discovered
    2. Dong bo tien trinh phu thuoc DAG: neu u la cha cua v thi s_disc(u) <= s_disc(v)
    3. Gan deadline_sprint (b_i) theo chuan SLA
    4. Dong bo nguoc Backward DAG Monotonicity: neu u la cha cua v thi b_u <= b_v
    5. Bao toan 1 <= s_disc <= b_i <= num_sprints
    """
    v_map = {v["id"]: v for v in vulnerabilities}

    # 1. Sap xep theo commit_timestamp
    sorted_vulns = sorted(vulnerabilities, key=lambda x: x.get("commit_timestamp", 0.0))
    n = len(sorted_vulns)
    chunk_size = max(1, n // num_sprints)

    for idx, item in enumerate(sorted_vulns):
        sprint_idx = min(num_sprints, (idx // chunk_size) + 1)
        item["sprint_discovered"] = sprint_idx
        item["earliest_sprint"] = sprint_idx

    # 2. Dong bo thuan ve phat hien: u -> v thi u phai duoc phat hien truoc hoac cung sprint voi v
    loop = True
    while loop:
        loop = False
        for v in vulnerabilities:
            s_curr = v["sprint_discovered"]
            for pid in v.get("predecessors", []):
                pred = v_map.get(pid)
                if pred and pred["sprint_discovered"] > s_curr:
                    pred["sprint_discovered"] = s_curr
                    pred["earliest_sprint"] = s_curr
                    loop = True

    # 3. Gan deadline SLA
    for v in vulnerabilities:
        r_i = v.get("r_i", 5.0)
        s_disc = v.get("sprint_discovered", 1)
        if r_i >= 9.0:
            delta = 1
        elif r_i >= 7.0:
            delta = 2
        elif r_i >= 4.0:
            delta = 3
        else:
            delta = 4
        v["deadline_sprint"] = min(s_disc + delta, num_sprints)

    # 4. Dong bo nguoc DAG Monotonicity: u -> v thi b_u <= b_v
    loop = True
    while loop:
        loop = False
        for v in vulnerabilities:
            b_curr = v["deadline_sprint"]
            for pid in v.get("predecessors", []):
                pred = v_map.get(pid)
                if pred and pred["deadline_sprint"] > b_curr:
                    pred["deadline_sprint"] = b_curr
                    loop = True

    return vulnerabilities
