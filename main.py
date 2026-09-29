import json
import sys
from pathlib import Path

# them thu muc hien tai vao path de import module
sys.path.append(str(Path(__file__).resolve().parent))

from src.parser import build_vulnerabilities
from src.mock_generator import build_teams, build_sprints


def save_jsonl(data: list, out_path: Path):
    # ghi danh sach thanh file jsonl
    with open(out_path, "w", encoding="utf-8") as f:
        for row in data:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main():
    root = Path(__file__).resolve().parent
    raw_path = root / "raw" / "train_ticket_positive_gold.jsonl"
    target_dir = root / "target"
    target_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Reading raw data...")
    vulns = build_vulnerabilities(str(raw_path))
    teams = build_teams()
    sprints = build_sprints()

    save_jsonl(vulns, target_dir / "vulnerabilities_backlog.jsonl")
    save_jsonl(teams, target_dir / "teams.jsonl")
    save_jsonl(sprints, target_dir / "sprints.jsonl")

    print(f"[+] Saved {len(vulns)} vulns -> target/vulnerabilities_backlog.jsonl")
    print(f"[+] Saved {len(teams)} teams -> target/teams.jsonl")
    print(f"[+] Saved {len(sprints)} sprints -> target/sprints.jsonl")
    print("[SUCCESS] Done.")


if __name__ == "__main__":
    main()
