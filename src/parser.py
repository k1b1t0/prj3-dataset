import json
from datetime import datetime
from rules import get_skill, get_risk, get_effort, make_title
from mock_generator import assign_sprint_timeline_and_sla


def build_vulnerabilities(raw_path: str, num_sprints: int = 8) -> list:
    # doc du lieu tho
    items = []
    with open(raw_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                items.append(json.loads(line))

    result = []
    auth_vuln_id = None
    by_module = {}

    for item in items:
        # dung luon id so nguyen goc
        raw_id = item["id"]
        f_path = item.get("file_path", "")
        parts = f_path.split("/")
        asset = parts[0] if len(parts) > 1 else "ts-root-service"

        # parse author_date thanh commit_timestamp
        d_str = item.get("author_date")
        try:
            commit_ts = datetime.fromisoformat(d_str).timestamp() if d_str else 0.0
        except Exception:
            commit_ts = 0.0

        cwes = item.get("cwe", [])
        primary_cwe = cwes[0] if cwes else "CWE-Other"
        skill = get_skill(cwes)
        r_i = get_risk(item.get("severity", "MEDIUM"), f_path)
        title = make_title(item.get("rule_id", ""))
        e_i = get_effort(cwe=primary_cwe, title=title, file_path=f_path, s_line=item.get("s_line"), e_line=item.get("e_line"))
        t_i = round(e_i * 4.0, 1)

        if asset == "ts-auth-service" and auth_vuln_id is None:
            auth_vuln_id = raw_id

        v = {
            "id": raw_id,
            "title": title,
            "cwe": primary_cwe,
            "repository": item.get("repo", "https://github.com/FudanSELab/train-ticket"),
            "asset_module": asset,
            "r_i": r_i,
            "e_i": e_i,
            "effort_points": e_i,
            "t_i": t_i,
            "skill": skill,
            "commit_timestamp": commit_ts,
            "sprint_discovered": 1,
            "earliest_sprint": 1,
            "deadline_sprint": 1,
            "predecessors": [],
            "fixing_info": {
                "commit_id": item.get("commit_id"),
                "parent_commit": item.get("parent_commit"),
                "file_path": f_path,
                "s_line": item.get("s_line"),
                "e_line": item.get("e_line"),
                "lines_range": f"{item.get('s_line')}-{item.get('e_line')}"
            },
            "consensus_audit": {
                "label": item.get("label"),
                "tier": item.get("tier"),
                "n_tools_ran": item.get("n_tools_ran"),
                "n_tools_agree": item.get("n_tools_agree"),
                "agreeing_tools": item.get("agreeing_tools", []),
                "finding_in_diff": item.get("finding_in_diff"),
                "confidence": item.get("confidence")
            },
            "diff_context": {
                "diff_parsed": item.get("diff_parsed", {}),
                "lines_added": item.get("lines_added"),
                "lines_deleted": item.get("lines_deleted")
            }
        }
        result.append(v)
        by_module.setdefault(asset, []).append(v)

    # phan nhom theo repository va module: quan he phu thuoc (precedence) chi ap dung noi bo trong cung 1 module/service
    by_repo_module = {}
    for v in result:
        repo = v["repository"]
        mod = v["asset_module"]
        by_repo_module.setdefault((repo, mod), []).append(v)

    # quy tac intra-service / intra-module:
    # trong cung microservice cua 1 repo, loi cau hinh (SecurityConfig, WebSecurityConfig, AuthConfig) phai sua truoc logic (Controller)
    for (repo, mod), v_list in by_repo_module.items():
        configs = [x for x in v_list if any(k in x["fixing_info"]["file_path"] for k in ["SecurityConfig", "WebSecurityConfig", "AuthConfig"])]
        controllers = [x for x in v_list if "Controller" in x["fixing_info"]["file_path"]]
        if configs and controllers:
            cfg_id = configs[0]["id"]
            for ctrl in controllers:
                if cfg_id != ctrl["id"] and cfg_id not in ctrl["predecessors"]:
                    ctrl["predecessors"].append(cfg_id)

    # Gan sprint timeline va SLA deadline dong bo voi DAG
    result = assign_sprint_timeline_and_sla(result, num_sprints=num_sprints)

    return result
