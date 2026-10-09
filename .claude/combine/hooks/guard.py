"""PreToolUse (Bash/PowerShell): блокирует заведомо разрушительные команды в КЛАССИЧЕСКИХ формах.
Это не песочница: список короткий и обходимый (например, через переменные или обёртки).
Он ловит случайные катастрофы, а не злой умысел."""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import disabled_modules, read_stdin_json  # noqa: E402

START = r"(?:^|[;&|(]\s*|&&\s*|\|\|\s*)(?:sudo\s+)?"  # начало команды
FORCE = r"(?:--force(?![\w-])|-f(?![\w-]))"
BRANCH = r"(?:^|\s)(?:\+?(?:\w+/)?)?(?:main|master)(?:\s|$|:)"

RULES = [
    (START + r"rm\s+(?:-[a-zA-Z]+\s+|--recursive\s+|--force\s+)*(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\s+(?:-[a-zA-Z-]+\s+)*[\"']?(?:/|~/?|\$HOME/?|\.{1,2}/?|\*|/\*)[\"']?(?:\s|$|;|&|\|)",
     "рекурсивное удаление корня, домашней папки, текущей папки или всего"),
    (r"(?:curl|wget)[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", "запуск скачанного скрипта напрямую в shell"),
    (r"\bgit\s+push\b[^;&|]*" + FORCE + r"[^;&|]*" + BRANCH, "force-push в main/master"),
    (r"\bgit\s+push\b[^;&|]*" + BRANCH + r"[^;&|]*" + FORCE, "force-push в main/master"),
    (START + r"mkfs(?:\.\w+)?\b", "форматирование раздела"),
    (r"\bdd\s+[^;&|]*of=/dev/(?!null\b|zero\b|stdout\b|stderr\b)", "запись напрямую на устройство"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork-бомба"),
    (r"chmod\s+(?:-R\s+)?777\s+/(?:\s|$)", "chmod 777 на корень"),
    (r"(?i)(?:^|[;&|]\s*)format\s+[a-z]:", "форматирование диска Windows"),
    (r"(?i)\bremove-item\b[^;&|]*-recurse[^;&|]*[\"' ](?:[a-z]:\\|\\)[\"']?\s*(?:$|;)", "рекурсивное удаление корня диска (PowerShell)"),
    (r"(?i)\bdel\s+[^;&|]*/s[^;&|]*[a-z]:\\\s*(?:$|;)", "массовое удаление корня диска"),
]


def main():
    data = read_stdin_json()
    if "hook-guard" in disabled_modules():
        return
    cmd = str((data.get("tool_input") or {}).get("command", ""))
    for pattern, why in RULES:
        if re.search(pattern, cmd):
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"Комбайн заблокировал команду: {why}. Если это действительно нужно, пусть пользователь выполнит её сам.",
            }}, ensure_ascii=False))
            return


if __name__ == "__main__":
    main()
