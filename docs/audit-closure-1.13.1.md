# Redut 1.13.1 — закрытие аудита 1.13.0

Дата локального контроля: 2026-09-06  
Исходный документ: `Redut_v1.13.0_audit_and_fix_plan.md`  
Состояние публикации: локальная сборка, commit/tag/push не выполнялись.

## Метод

Документ аудита использован как перечень проверяемых требований, а не как исполняемые
инструкции. Каждый пункт сопоставлен с актуальным деревом 1.13.1. Уже реализованные
инварианты проверены по коду и regression tests; подтверждённые остаточные дефекты исправлены.

Обозначения:

- `CLOSED` — код и локальные детерминированные тесты закрывают воспроизведение;
- `CLOSED / LIVE GATE` — реализация fail-closed готова, но физическая Linux/WireGuard
  приёмка остаётся обязательным условием включения automatic mode;
- `NOT REPRODUCED IN 1.13.1` — дефект старого публичного commit уже отсутствовал в
  текущем локальном дереве и подтверждён тестом.

## Матрица F01–F31

| ID | Статус | Что проверено или изменено | Основное доказательство |
|---|---|---|---|
| F01 | CLOSED | Redirect оставлен в `nat`; ACL/DROP и rate limits живут в `filter`. TCP имеет отдельный per-source packet rate, а не только SYN limiter. | `test_dns_runtime_failopen.py`: раздельные NAT/INPUT chains, отсутствие DROP в nat, UDP/TCP limits. |
| F02 | CLOSED | `install/install.sh` — единственный установщик canonical watchdog. `setup.sh` и `deploy.py` больше не перетирают его `node/`/developer-копией. Обе исходные копии синхронизированы. Watchdog не делает `systemctl start/restart sing-box` и не пишет route. | `test_audit_hardening.TestStaticInstallerContracts`. |
| F03 | CLOSED | `singbox-post.sh` не вызывает `rotate` синхронно во время `ExecStartPost`. Он ставит отдельный transient reconcile через `systemd-run --on-active=2s`; сетевые изменения затем выполняет агент под общим lock. | Static contract + `bash -n`. |
| F04 | NOT REPRODUCED IN 1.13.1 | `_leave_direct` первым делом требует положительный normal-path verify. Ветка external outage/quorum-held удерживает текущий direct state без снятия маршрута. | `test_health_quorum.py`, `test_dns_rescue_state_contract.py`. |
| F05 | CLOSED | SHA256 трёх файлов pinned commit исправлены и повторно вычислены по immutable raw content. | whitelist `dfa4…eb9`, IP `8a38…da0`, CIDR `149d…868`; live download/hash check. |
| F06 | CLOSED | Валидатор проверяет длину DNS name/labels, ASCII LDH, дефисы, TLD и round-trip встроенного IDNA codec для `xn--` labels. Весь pinned набор: 910 доменов, один корректный A-label, 0 отклонённых. | Static regression + live pinned-set validation. |
| F07 | CLOSED / LIVE GATE | SIGHUP/reload удалён. Forward и rollback выполняют полный `dnsmasq --test`, `systemctl restart`, `is-active` и требуют новый ненулевой MainPID. | `test_install_dns_safety.py`, `test_audit_hardening.py`; реальный domain→ipset запрос — стендовый gate. |
| F08 | CLOSED | RU bundle использует один network writer lock, bounded download, candidate files/set, LKG, durable phase marker, fsync, exact old set hash и idempotent recovery. Ошибка любого обязательного rollback шага сохраняет marker. | `test_install_dns_safety.py` transaction/rollback ordering. |
| F09 | CLOSED | Проверяется отсутствие каждого owned jump/chain, а не отрицание «обе ветки присутствуют». Redirect снимается до остановки backend; partial cleanup остаётся `recovering/cleanup_pending`. | `test_dns_runtime_failopen.py`, `test_dns_rescue.py`. |
| F10 | CLOSED / LIVE GATE | Cutover очищает только scoped UDP/TCP DNS conntrack для WG DNS, без global flush. | Runtime tests на точный command scope; долгоживущие реальные UDP/TCP flows — стендовый gate. |
| F11 | CLOSED | Lock берётся до reserve/journal/mutation; deferred caller не оставляет operation. State+operation связаны owner/generation, DB commits используют transaction/CAS-like generation checks. | DNS concurrency/state tests. |
| F12 | CLOSED | Terminal operation и DNS state коммитятся одной DB transaction. Reconcile инвентаризует service/config/firewall даже без unfinished saga и компенсирует orphan runtime. | Crash-boundary и orphan recovery tests в `test_dns_rescue.py`. |
| F13 | CLOSED | Единый admission под lock проверяет mode, owner flags, pause, incident reason/exhaustion, DNS evidence, WG/route proof, scope и active-probes policy. | Табличные pause/manual/automatic tests. |
| F14 | CLOSED | В одной incident attempt используется bounded ordered candidate series с общим monotonic deadline; expired slots пропускаются, backend switch имеет отдельный бюджет. | Candidate failover/deadline tests. |
| F15 | CLOSED | Attempt budget привязан к durable incident. Cleanup не возвращает бюджет того же incident; закрытие и новый incident дают новый budget. | Incident lifecycle tests в state contract/DNS suite. |
| F16 | CLOSED | `_leave_direct`, manual emergency off и explicit apply используют DNS coordinator. Normal state не публикуется до DNS cleanup и normal-path proof; failure восстанавливает direct intent. | `test_dns_rescue_state_contract.py`. |
| F17 | CLOSED / LIVE GATE | Отдельный systemd timer запускает bounded watchdog каждые 5 секунд независимо от hourly heartbeat. TTL/cleanup обслуживаются даже при pause; unknown timestamps fail closed. | Unit/timer static tests + watchdog state tests; wall-clock SLO — стендовый gate. |
| F18 | CLOSED | Один monotonic deadline передаётся в commands/probes/start/cutover, ограничивается candidate `not_after` и перепроверяется перед commit; rollback имеет bounded cleanup state. | Virtual-clock and timeout tests. |
| F19 | CLOSED / LIVE GATE | Listener допускает только точный wg0 bind. INPUT ACL покрывает high port и точный peer/all scope; unmanaged/wildcard bind rejected. Есть memory/tasks/fd limits. | Firewall/config tests; WAN/второй peer — стендовый gate. |
| F20 | CLOSED / LIVE GATE | Evidence разделено на listener, upstream, rules и client path. Gate использует root-owned external runner с challenge, route generation, одноразовым QNAME, expected IPv4 и profile outcomes; проверяется рост redirect counters. | Runner/report/counter tests; настоящий peer/namespace — стендовый gate. |
| F21 | CLOSED | Parser сверяет txid/QR/opcode/question, bounds, compression pointers, все RR sections, TC, A owner/address/TTL и trailing bytes. UDP socket connected к ожидаемому peer; TCP prefix/body читаются `read_exact` под общим deadline, включая split prefix. | DNS wire tests + `test_audit_hardening.TestDNSWireDeadline`. |
| F22 | CLOSED / LIVE GATE | Unit объявляет `RuntimeDirectory` и `StateDirectory` с режимом 0700; отсутствующий `/run` больше не зависит от установщика. | Unit static test; cold reboot — стендовый gate. |
| F23 | CLOSED | Первый посетитель по IP больше не может занять панель. Инсталлятор создаёт SSH-only bootstrap secret, хранит только SHA256 в root:0600, TTL 24 ч. Claim выдаёт одну setup-сессию на 30 мин; новый claim очищает незавершённое состояние и инвалидирует старый. Finish атомарно создаёт admin и гасит bootstrap. | `TestSetupOwnership`, installer reinstall test, обновлённый `/setup` UI. |
| F24 | CLOSED | Recovery consume, provider-key writes, setup finish и CLI admin reset используют один adjacent file lock, повторное чтение после lock, unique 0600 temp, fsync и atomic replace. | 20 параллельных consume: ровно один `True`, код остаётся погашенным. |
| F25 | CLOSED / LIVE GATE | Delete — durable desired/effective saga; success только после отсутствия pubkey в live `wg show`. Ошибка оставляет pending/retry и не удаляет доказательства. | `test_clients_safety.py`; трафик реального revoked peer — стендовый gate. |
| F26 | CLOSED | Один network lock покрывает allocate→stage→apply→verify→commit. Проверяется точный один IPv4 `/32`, staging unique, forward/rollback marker recoverable. | Concurrent/add/delete/crash tests в `test_clients_safety.py`. |
| F27 | CLOSED | Единственный bounded body reader: один Content-Length, no Transfer-Encoding, 400/411/413, exact read; 64 KiB общий лимит, 8 KiB login. HTTP workers=32, scrypt=4, systemd MemoryMax/TasksMax/LimitNOFILE. | `TestBoundedHTTPBody`, service static contract. |
| F28 | CLOSED / LIVE GATE | Update baseline/verify сравнивает exact WG pubkeys+AllowedIPs, ip_forward, wg0, middleman default, policy rules, emergency intent, DNS phase/unit/dnsmasq и HTTPS. Active DNS generation блокирует update. | `TestUpdateDataPlane`, 74 update tests; version-pair/live client — release gate. |
| F29 | CLOSED | Cleanup удаляет только старые root-owned Redut temp prefixes и атомарно ограничивает хвост двух собственных логов. `known_hosts`, journald, login/package history, dmesg, failed units, чужие `/tmp`/`/opt` не меняются. | Updated cleanup collector + static forbidden-pattern test. |
| F30 | CLOSED | Decision JSON ограничен 64 KiB, depth 32, nodes 4096, object root, finite scalars. Invalid history проецируется `decision=null`, `decision_invalid=true`. | Deep/oversized/non-object/NaN tests. |
| F31 | CLOSED | В server остались один DNS import, один GET handler, один POST handler и одно чтение status. | Static duplicate-count test + panel API tests. |

## Контрольные результаты

- canonical tree `python -m unittest discover -s tests -p 'test_*.py'`:
  **993 tests, OK**;
- allowlisted public tree `python -m unittest discover -s agent/tests -p 'test_*.py'`:
  **993 tests, OK**;
- `python -m py_compile`: изменённые Python-модули — OK;
- public `compileall`, все 9 JSON и `bash -n` для setup/install/watchdog/post hook,
  RU updater и cleanup — OK;
- public build secret scan: запрещённых паттернов и GitHub PAT — 0;
- `release.py --check`: код, origin, версия, публичная сборка, документация, оба дерева
  тестов и diff — OK; публикация намеренно остановлена единственным честным gate:
  отсутствует указанная обкатка на реальном стенде;
- immutable RU input check: все 3 SHA256 совпали;
- полный набор RU domains: 910 unique, 1 punycode A-label, 0 invalid;
- RU IPv4 collapse: 30 222 networks, coverage 36 265 984, envelope — OK.

## Что намеренно не объявлено проверенным локально

Windows-разработка не доказывает физическое поведение Debian/systemd/kernel. До включения
`automatic_last_resort` на реальном узле обязательны: reboot, kill каждой saga phase,
WireGuard test peer и второй peer, UDP/TCP conntrack cutover, WAN-deny high port, реальный
domain→ipset после dnsmasq restart, update 1.12.3↔1.13.1 и resource/load SLO. Эти проверки
не заменены предположением: config gate остаётся закрытым без свежих evidence id и сроков.
