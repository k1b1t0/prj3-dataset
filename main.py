import json
import sys
from pathlib import Path
from collections import Counter

# them thu muc hien tai va thu muc src vao path de import module
sys.path.append(str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent / "src"))

from src.parser import build_vulnerabilities
from src.mock_generator import build_teams, build_sprints, calculate_optimal_sprints


def save_jsonl(data: list, out_path: Path):
    # ghi danh sach thanh file jsonl
    with open(out_path, "w", encoding="utf-8") as f:
        for row in data:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main():
    root = Path(__file__).resolve().parent
    raw_path = root / "raw" / "combined_positive_gold_silver.jsonl"
    target_dir = root / "target"
    target_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Reading raw data & parsing vulnerabilities...")
    teams = build_teams()
    team_total_cap = sum(t["capacity_sp"] for t in teams)

    # Khoi tao voi so sprint mac dinh K=8
    num_sprints = 8
    vulns = build_vulnerabilities(str(raw_path), num_sprints=num_sprints)

    total_effort = sum(v["e_i"] for v in vulns)
    optimal_k = calculate_optimal_sprints(total_effort, team_capacity_per_sprint=team_total_cap)
    if optimal_k != num_sprints:
        num_sprints = optimal_k
        vulns = build_vulnerabilities(str(raw_path), num_sprints=num_sprints)

    sprints = build_sprints(num_sprints=num_sprints, budget_sp=team_total_cap)

    save_jsonl(vulns, target_dir / "vulnerabilities_backlog.jsonl")
    save_jsonl(teams, target_dir / "teams.jsonl")
    save_jsonl(sprints, target_dir / "sprints.jsonl")

    # In thong ke chi tiet e_i
    counts = Counter(v["e_i"] for v in vulns)
    total_v = len(vulns)
    print("\n" + "=" * 50)
    print(f"[*] THONG KE PHAN PHOI EFFORT e_i (Tong: {total_v} findings, {total_effort} SP):")
    for k in [1, 2, 3, 5, 8]:
        cnt = counts.get(k, 0)
        pct = (cnt / max(1, total_v)) * 100
        print(f"    - e_i = {k} SP: {cnt:4d} tasks ({pct:5.2f}%)")

    # Thong ke timeline va deadline
    sprint_counts = Counter(v["sprint_discovered"] for v in vulns)
    print(f"[*] SO SPRINTS DONG K = {num_sprints}")
    print("    - Phan bo discovery theo sprint:")
    for s_idx in range(1, num_sprints + 1):
        print(f"      Sprint {s_idx}: {sprint_counts.get(s_idx, 0)} findings")
    print("=" * 50)

    print(f"[+] Saved {len(vulns)} vulns -> target/vulnerabilities_backlog.jsonl")
    print(f"[+] Saved {len(teams)} teams -> target/teams.jsonl")
    print(f"[+] Saved {len(sprints)} sprints -> target/sprints.jsonl")
    print("[SUCCESS] Done.")


if __name__ == "__main__":
    main()
