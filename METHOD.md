# Методика и границы корреляции

- UTC используется для сопоставления времени. При реальном расследовании нужно измерить clock skew и задержку доставки.
- Первый кейс группирует по IP + username + host. Успешный вход сбрасывает последовательность. Временное окно 600 секунд включительно.
- Второй кейс связывает 4624.TargetLogonId с SubjectLogonId на **том же хосте**, ограничивая цепочку 20 минутами. SID созданного аккаунта должен совпасть с MemberSid добавления в группу. Одной близости timestamps недостаточно.
- LogonId локален для хоста и может переиспользоваться после перезагрузки. В реальных данных требуется контекст загрузки ОС/длительности сессии; этот компактный dataset его не моделирует.
- По одному 4697 нельзя заключить, что служба запустилась или выполнила вредоносный код. По одному 1102 нельзя доказать намерение скрыть атаку.
- В кейсе 02 все изменения приписываются сессии исходного администратора. Созданный аккаунт не объявляется исполнителем службы: таких данных нет.
- Синтетические наборы малы; replay — прозрачная reference-реализация для разбора, не высокопроизводительный коррелятор.

## Источники для сопоставления событий

- [Microsoft 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [Microsoft 4732](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732)
- [Microsoft 4697](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697)
- [Microsoft 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)

Ссылки объясняют поля и аудит Windows; они не подтверждают синтетические события лаборатории.
