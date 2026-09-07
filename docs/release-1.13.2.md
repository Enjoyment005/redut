# Редут 1.13.2 — исправления подтверждённых дефектов аудита

Дата: 2026-09-07

## Итог

Patch-релиз закрывает подтверждённые A01–A19 повторного аудита 1.13.1. Новых режимов
автоматически не включает: DNS Rescue остаётся fail-closed и требует отдельных live evidence.
Полная матрица исправлений, локальных доказательств и внешних stop-gates приведена в
[`audit-closure-1.13.1.md`](audit-closure-1.13.1.md).

## Основные изменения

- совместимый legacy lock handoff для updater 1.12.3/1.13.0 и авторитетный post-lock
  DNS/dataplane admission во всех install/deploy путях;
- durable resume после reconcile, точный primary canary bypass и строгий empty-proof
  conntrack-tools 1.4.8;
- reboot-safe RU allowlist snapshot/rollback, offline recovery и always-attached static set;
- немедленный отзыв старых административных сессий через credential epoch;
- durable exact-request протокол buy/prolong между CLI, web и automation job без двойной траты;
- revision-safe background config writes и соблюдение `active_probes=false`;
- единый base manifest, корректные 400/411/413, полная видимость peer inventory и
  lifecycle-aware setup exit status;
- remote secret staging получает `root:0600` до первого секретного байта; bootstrap dry-run
  маскирует пароли;
- публичная Linux/Debian workflow и executable crash/failure regressions.

## Проверки

- public и canonical: **1107 tests, OK (skipped=2 на Windows)**;
- независимый аудит каждого шага и итогового diff: PASS;
- real-shell RU recovery matrix: 6 методов, все forward/rollback/commit subcases — PASS;
- Python compile, 9 JSON, `bash -n`, `git diff --check` — PASS.

Windows-пропуски относятся только к настоящим Linux `flock` и `pidfd_getfd`. До включения
release в production обязательны отдельные Debian 13 проверки tagged updater, systemd,
iptables/conntrack/WireGuard, reboot/power-loss, OpenSSH SFTP, browser reset и provider
sandbox reconciliation. Публикация кода не считается выполнением этих live gates.
