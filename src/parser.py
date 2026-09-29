import json
from src.rules import get_skill, get_risk, get_effort, get_deadline, make_title


def build_vulnerabilities(raw_path: str) -> list:
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

        cwes = item.get("cwe", [])
        primary_cwe = cwes[0] if cwes else "CWE-Other"
        skill = get_skill(cwes)
        r_i = get_risk(item.get("severity", "MEDIUM"), f_path)
        e_i = get_effort(item.get("s_line"), item.get("e_line"))
        t_i = round(e_i * 4.0, 1)
        title = make_title(item.get("rule_id", ""))

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
            "t_i": t_i,
            "skill": skill,
            "earliest_sprint": 1,
            "deadline_sprint": get_deadline(r_i),
            "predecessors": [],
            "fixing_info": {
                "commit_id": item.get("commit_id"),
                "file_path": f_path,
                "lines_range": f"{item.get('s_line')}-{item.get('e_line')}"
            }
        }
        result.append(v)
        by_module.setdefault(asset, []).append(v)

    # quy uoc 1: trong cung microservice, cau hinh (SecurityConfig) phai sua truoc logic (Controller)
    for mod, v_list in by_module.items():
        configs = [x for x in v_list if "SecurityConfig" in x["fixing_info"]["file_path"]]
        controllers = [x for x in v_list if "Controller" in x["fixing_info"]["file_path"]]
        if configs and controllers:
            cfg_id = configs[0]["id"]
            for ctrl in controllers:
                if cfg_id not in ctrl["predecessors"]:
                    ctrl["predecessors"].append(cfg_id)

    # quy uoc 2: service call graph - auth service phai duoc va truoc user service va payment service
    if auth_vuln_id:
        target_services = {"ts-user-service", "ts-inside-payment-service"}
        for v in result:
            if v["asset_module"] in target_services and v["id"] != auth_vuln_id:
                if auth_vuln_id not in v["predecessors"]:
                    v["predecessors"].append(auth_vuln_id)

    # lan truyen nguoc deadline de dam bao b_pred <= b_succ (tranh bay vo nghiem)
    v_map = {v["id"]: v for v in result}
    loop = True
    while loop:
        loop = False
        for v in result:
            b_curr = v["deadline_sprint"]
            for pid in v["predecessors"]:
                pred = v_map.get(pid)
                if pred and pred["deadline_sprint"] > b_curr:
                    pred["deadline_sprint"] = b_curr
                    loop = True

    return result
