---
id: G25
module: core
title: Побічний ефект на рівні модуля
---
**Симптом:** весь набір тестів перестає збиратись (`ValueError: I/O operation on closed file`), хоча тест імпортує одну чисту функцію. Симптом не вказує на винуватця: падає collection, а не assert.
**Корінь:** зручність для людини за консоллю вбудована в модуль. Файл, який можуть імпортувати, не має права міняти глобальний стан процесу.
**Правило:** усе, що чіпає глобальний стан (`sys.stdout`, локаль, `logging.basicConfig`, `os.chdir`, створення тек), лише під `if __name__ == "__main__"` або у функції, яку кличе `main()`. На рівні модуля лише визначення й константи, без вводу-виводу.
**Перевірка:** `python -c "import scripts.tool"` нічого не друкує й нічого не змінює; `pytest --collect-only -q` збирається.
**Приклад:**
```python
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")  # у тілі модуля: ламає pytest

def main():
    sys.stdout.reconfigure(encoding="utf-8")  # правильно: лише при запуску

if __name__ == "__main__":
    main()
```
