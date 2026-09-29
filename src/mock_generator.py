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


def build_sprints() -> list:
    # tao danh sach sprint
    return [
        {"sprint_id": 1, "name": "Sprint 1", "budget_sp": 40},
        {"sprint_id": 2, "name": "Sprint 2", "budget_sp": 40},
        {"sprint_id": 3, "name": "Sprint 3", "budget_sp": 40},
        {"sprint_id": 4, "name": "Sprint 4", "budget_sp": 40}
    ]
