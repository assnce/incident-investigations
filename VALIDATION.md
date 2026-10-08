# Проверка первой версии

Дата: 2026-10-08. Среда: Python 3.12.14, Linux.

```bash
python replay.py --check
python -m unittest -v
```

Результат фактического запуска: 6 unit-тестов; 19 синтетических событий, 2 findings, SHA-256 evidence проверены.

CI пока не настроен. Это локально выполненные проверки, а не статус GitHub Actions.
