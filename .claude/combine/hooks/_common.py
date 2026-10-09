"""Общие функции хуков Комбайна. Только стандартная библиотека."""
import json
import os
import sys

ALL_HOOKS = {"hook-state", "hook-remind", "hook-guard"}


def project_dir():
    return os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()


def disabled_modules():
    """Отключённые модули/ключи: из .combine.json проекта и из COMBINE_DISABLE.
    COMBINE_DISABLE=all выключает все три хука."""
    off = set()
    try:
        with open(os.path.join(project_dir(), ".combine.json"), encoding="utf-8") as f:
            off.update(json.load(f).get("disabled", []))
    except (OSError, ValueError):
        pass
    off.update(x.strip() for x in os.environ.get("COMBINE_DISABLE", "").split(",") if x.strip())
    if "all" in off:
        off |= ALL_HOOKS
    return off


def force_utf8():
    """На Windows stdout по умолчанию в системной кодировке, а Claude Code читает UTF-8."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass


def read_stdin_json():
    force_utf8()
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        return json.loads(raw or "{}")
    except (ValueError, OSError):
        return {}
