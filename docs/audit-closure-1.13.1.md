# Redut 1.13.2 — закрытие подтверждённых дефектов аудита 1.13.1

Дата локального контроля: 2026-09-07

Исходный документ: `Redut_v1.13.1_audit_and_fix_plan.md`

Ветка реализации: `fix/v1.13.1-audit-confirmed`

Релиз: `v1.13.2`; production deploy не входит в эту публикацию.

## Метод

Документ аудита использован только как перечень требований и воспроизведений. Исправлялись
лишь подтверждённые A01–A19. Работа велась малыми шагами: фокусный regression, изменение,
повторный regression и независимая проверка другим агентом. После закрытия пунктов выполнен
повторный сквозной аудит; найденные им остатки в A03/A04/A06/A08/A19 также получили
исполняемые регрессии до итогового PASS.

`CLOSED` ниже означает закрытие локального code/model воспроизведения. `LIVE GATE` честно
оставляет физическую проверку Debian/systemd/kernel/provider до production rollout и
включения automatic DNS.

## Матрица A01–A19

| ID | Статус | Закрытый инвариант и локальное доказательство |
|---|---|---|
| A01 | CLOSED / LIVE GATE | Старый updater передаёт именно своё locked open-file-description через pinned pidfd; все same-inode FD удерживаются до probe. `test_legacy_lock_handoff.py` проверяет multi-FD/death/PID-reuse ошибки. Реальные tagged 1.12.3/1.13.0 + Yama остаются live gate. |
| A02 | CLOSED / LIVE GATE | DROP/ACL вынесены из `nat` в owned `filter` chains; активация и fail-open проверяют точные jumps/chains. Реальный iptables/WG dataplane остаётся live gate. |
| A03 | CLOSED / LIVE GATE | Авторитетные DNS phase/unit и dataplane baseline читаются после общего lock перед первой mutation. Setup/install/bootstrap/deploy используют fail-closed preflight; missing/blank singleton и dangling symlink артефакты не считаются fresh. |
| A04 | CLOSED / LIVE GATE | Reconcile перед detach сохраняет durable resume descriptor для принадлежащего активного поколения, включая временно неизвестный boot id; orphan по-прежнему не возобновляется. Реальная service/route drift проверка остаётся live gate. |
| A05 | CLOSED / LIVE GATE | Primary recovery canary использует точный terminal bypass, поэтому пакет не возвращается в прежний GLOBAL REDIRECT. Модель проверяет UDP/TCP counters и cleanup; реальный WG peer остаётся live gate. |
| A06 | CLOSED / LIVE GATE | rc=1 delete допускается только с точной zero-deleted сводкой; list доказывает отсутствие strict empty XML либо реальным для conntrack-tools 1.4.8 `rc0 + blank stdout + exact zero-shown stderr`. Blank/blank, malformed, permission и residual flow отклоняются. |
| A07 | CLOSED / LIVE GATE | Boot всегда создаёт пустой `ru_whitelist_net` и прикрепляет owned RETURN rule; первый updater атомарно наполняет уже используемый set. Реальный reboot/iptables остаётся live gate. |
| A08 | CLOSED / LIVE GATE | До `prepared` сохраняется проверяемый durable snapshot старого live set. Real-shell harness исполняет 8 forward boundaries, commit boundary, 5 повторных падений rollback, reboot wipe всех sets, ABSENT-old и create/swap/restart failures; recovery offline и идемпотентен. Power-loss/fsync на Debian остаётся live gate. |
| A09 | CLOSED | Admin credential epoch входит в session contract. Reset пароля/TOTP/recovery атомарно меняет epoch, и старые cookies не проходят после перезапуска или login/reset interleaving. |
| A10 | CLOSED / LIVE GATE | Buy/prolong получают stable request id и durable SQLite phases. `submitted` ambiguity блокирует новую трату до read-only reconciliation; точный replay не мутирует повторно. Отдельные процессы и automation jobs проверены; настоящая sandbox-покупка остаётся live gate. |
| A11 | CLOSED | Config writes сравнивают owner revision/CAS; stale background snapshot не может вернуть отключённое владельцем auto-update. |
| A12 | CLOSED | `active_probes=false` соблюдается на новом входе и failover: активные кандидатные probes не запускаются, readiness не подделывается. |
| A13 | CLOSED | Единый base manifest охватывает watchdog/post/boot/cleanup; agent-only deploy запрещён поверх legacy payload без явного полного upgrade. |
| A14 | CLOSED | Remote secret/config writer принимает успех только по проверенному marker; любой nonzero/empty/transport failure сохраняет ошибку и не сообщает успешный deploy. |
| A15 | CLOSED | Inventory устройств отделён от readiness добавления: полная подсеть или legacy peer видимы, а кнопка add получает точную причину отказа. |
| A16 | CLOSED | Авторизованные handlers сохраняют типизированные 400/411/413 body-reader ошибки; invalid/non-object JSON не превращается в 500. |
| A17 | CLOSED / CI GATE | Публичная workflow запускает discovery из `agent` и real-shell regressions. Локально public discovery проходит; фактический GitHub Linux run обязателен до release. |
| A18 | CLOSED / LIVE GATE | Setup ждёт обязательный lifecycle, проверяет boot после него и возвращает nonzero при любом обязательном failure; success больше не печатается заранее. Реальный systemd install остаётся live gate. |
| A19 | CLOSED / LIVE GATE | Deploy и bootstrap создают exclusive handle, ставят/проверяют `root:0600` до первого секретного байта и атомарно публикуют; dry-run маскирует пароли. Observer-модели проходят; реальный OpenSSH SFTP остаётся live gate. |

## Локальный контроль

- полный public suite: **1107 tests, OK (skipped=2)**; на Windows пропущены только
  Linux-only реальные `flock` process gate и `pidfd_getfd` handoff;
- независимые фокусные проверки A01–A19 и финальный сквозной аудит: PASS;
- `py_compile`/`compileall`, JSON parse, `bash -n`, `git diff --check`: PASS;
- real-shell RU crash/recovery matrix: 6 methods, все boundary/failure subcases — PASS;
- production deploy и внешние денежные операции не выполнялись.

## Стоп-гейты перед production и включением automatic DNS

Нужен отдельный Debian 13 x86_64 стенд: tagged updater 1.12.3 и 1.13.0 с реальным
cron/systemd/Yama/pidfd; kill/contender/rollback/manual retry; reboot и power-loss на RU
транзакциях; настоящий iptables/conntrack/WireGuard peer для A02/A04–A08; browser E2E
reset-session; OpenSSH SFTP observer; sandbox buy/prolong с provider reconciliation; зелёная
GitHub Linux workflow. Публикация исходного кода не заменяет эти доказательства: до них
automatic DNS mode и production rollout остаются закрыты.
