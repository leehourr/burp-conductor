"""burp-conductor CLI — admin subcommands for the plugin.

Subcommands:
  install-skills   Copy .claude/commands/pentest-*.md into ~/.claude/commands/
                   so the slash commands resolve from any directory.

Not for the MCP server itself — that's `burp-stdio`.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
SKILL_SRC = REPO_ROOT / ".claude" / "commands"
SKILL_DST = Path.home() / ".claude" / "commands"


def cmd_install_skills(args: argparse.Namespace) -> int:
    if not SKILL_SRC.is_dir():
        print(f"error: skill source dir not found: {SKILL_SRC}", file=sys.stderr)
        return 1

    skills = sorted(SKILL_SRC.glob("pentest-*.md"))
    if not skills:
        print(f"error: no pentest-*.md skills under {SKILL_SRC}", file=sys.stderr)
        return 1

    SKILL_DST.mkdir(parents=True, exist_ok=True)

    copied, skipped = [], []
    for src in skills:
        dst = SKILL_DST / src.name
        if dst.exists() and not args.force:
            skipped.append(src.name)
            continue
        shutil.copy2(src, dst)
        copied.append(src.name)

    for name in copied:
        print(f"  installed  {name}")
    for name in skipped:
        print(f"  skipped    {name}  (exists; pass --force to overwrite)")
    print(f"\ndst: {SKILL_DST}")
    print(f"copied: {len(copied)}   skipped: {len(skipped)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="burp-conductor")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_install = sub.add_parser(
        "install-skills",
        help="copy pentest-* slash commands into ~/.claude/commands/",
    )
    p_install.add_argument(
        "--force", action="store_true", help="overwrite existing skills"
    )
    p_install.set_defaults(func=cmd_install_skills)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
