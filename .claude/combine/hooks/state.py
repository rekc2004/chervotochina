"""SessionStart: выводит статус комбайна и docs/TASK.md (его stdout попадает в контекст)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import disabled_modules, project_dir, read_stdin_json  # noqa: E402

MAX_CHARS = 8000


def main():
    read_stdin_json()
    off = disabled_modules()
    if "hook-state" in off:
        return
    lines = ["[Комбайн] активен. Правила: .claude/combine/CORE.md, конвейер: .claude/combine/pipeline.md."]
    if off - {"all"}:
        lines.append("Отключено пользователем (не использовать): " + ", ".join(sorted(off - {"all"})) + ".")
    task = os.path.join(project_dir(), "docs", "TASK.md")
    try:
        with open(task, encoding="utf-8") as f:
            text = f.read()
        if len(text) > MAX_CHARS:
            text = text[:MAX_CHARS] + "\n...[обрезано, полный файл: docs/TASK.md]"
        lines.append("Текущее состояние задачи (docs/TASK.md):\n" + text)
    except OSError:
        lines.append("docs/TASK.md отсутствует: задача ещё не начата или файл не создан.")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
