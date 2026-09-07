# Redut 1.13.3 — закрытие подтверждённых дефектов 1.13.2

Дата: 2026-09-07

Исходный отчёт: `Redut_v1.13.2_аудит_и_план.md`. Он использовался как набор
проверяемых гипотез, а не как инструкция к слепому применению patch-файла.

| ID | Статус | Доказанный итог |
|---|---|---|
| A01–A03 | CLOSED | Credential snapshot/recovery, strict emergency boolean, bounded reusable POST body и однозначный framing. |
| A04–A05 | CLOSED | Повтор mutating request только при proven-unsent; exception не раскрывает curl argv/секреты. |
| A06 | CLOSED / stricter | Proxy6 берёт live baseline; без provider correlation lost response остаётся `submitted`. ProxyLine prolong блокируется до мутации. |
| A07 | CLOSED | Provider listing валидируется до writer; merge/rollback/vanished queue атомарны, namespace не смешивается. |
| A08–A12 | CLOSED | Secret temp 0600, route replace ordering, exact IP token, strict restart/is-active и curl rc. |
| A13–A15 | CLOSED | Explicit proxy не обходится `NO_PROXY`; IP парсится `ipaddress`; unreadable config не снимает MANUAL. |
| A16–A17 | CLOSED | Panel/bootstrap failure не маскируется; ресурсы закрываются; live port проверяется до upload; non-/24 адреса корректны. |
| A18 | CLOSED | Update-state RMW сериализован; unique temp, fsync и concurrent-state regressions. |

Независимая проверка также подтвердила и закрыла остаточные границы, которых не было
в первоначальном patch: смешение RUB/USD, ложная атрибуция чужого expiry change,
порча score при inconclusive-пробе, redirect после mutating POST, duplicate/invalid HTTP framing,
бесконечное trickle-чтение, поздняя проверка panel port и non-/24 update address.

Отдельно от отчёта закрыт live-дефект 1.13.0 → 1.13.2: совместимая материализация
DNS Rescue singleton разрешена только для точного безопасного legacy-состояния; остальные
формы остаются fail-closed.

На live-canary VADIM до публикации дополнительно выявлены недопустимо длинные
INPUT-chain имена и ложная неопределённость `iptables-nft` при проверке ссылки на
отсутствующую owned-цепочку. Имена сокращены до лимита ядра, а ссылки теперь
сверяются с чтением родительской цепочки. Это убирает ложный `recovering`, не ослабляя
fail-closed поведение при реальной ошибке чтения firewall.

Тот же canary выявил потерю `middleman default` после автоматического перезапуска
sing-box: локальная проба через `tun0` оставалась успешной и ошибочно перекрывала
неработающий клиентский policy-route. Исправлена вся цепочка — watchdog видит drift
default/rule/effective FIB, агент восстанавливает маршрут только после нового `tun0`,
а неуспешный локальный repair при доказанно живом egress останавливается без обращения
к провайдерам и денежным операциям.

После основной canary-приёмки подтверждён отдельный дефект панели: `loadStatus()`
обращался к `drs`/`drc` вне области их объявления. Поэтому браузер успевал обновить
название узла и время, затем получал `ReferenceError`; маяк состояния зависал, а
карта выхода оставалась пустой. Объявление снимка DNS Rescue перенесено внутрь
`loadStatus()` до первого использования и защищено отдельным regression-тестом.

## Финальная локальная приёмка

Сборка 1.13.3 установлена на VADIM напрямую из локального canary-архива, без GitHub:
`UPDATE=1` завершился с `rc=0`, конфиг, ключи, клиенты и текущий upstream сохранены.
Хэши установленных `states.py`, `pool.py`, `update.py`, `dns_runtime.py` и watchdog
совпали с проверенным публичным деревом. На Debian пройден фокус
policy-route/DNS/setup (**77/77**), затем полный `vpn_healthcheck.py ru` без замечаний.

После нескольких тиков DNS watchdog состояние осталось `idle`, `last_error=NULL`,
все очереди операций пусты, DNS-сервис неактивен, owned firewall-артефактов нет.
Маршрут подтверждён тремя независимыми фактами: один `default dev tun0` в таблице
`middleman`, одно exact `fwmark 0x64` rule и marked lookup через `tun0`/`middleman`.
Здоровый тик sing-box watchdog не изменил PID, число рестартов или config hash.

Попытка безопасно создать второе идентичное policy-rule была атомарно отклонена
ядром (`File exists`) до изменения состояния. Единственное рабочее правило намеренно
не удалялось: это создало бы даже краткий fail-open в WAN. Ветки missing/duplicate
остаются покрыты изолированными тестами; реальный restart/setup проверил пересоздание
`tun0` и обязательный финальный route-gate. Публикация в GitHub по решению владельца
отложена; push, tag и release не выполнялись.

После приёмки `/opt/redut-src` под update-lock и network-lock синхронизирован с
принятым canary, чтобы будущий rollback не установил прежний route-код. Отдельное
дерево `/opt/redut-src.prev` версии 1.13.0 проверено по inode/hash и не изменялось;
временный серверный архив удалён только после повторной проверки здоровья.

UI-исправление применено на VADIM отдельной crash-recoverable транзакцией под теми
же lock: runtime и source-копия получили один проверенный SHA-256, после рестарта
подтверждены новый PID, точный ExecStart, HTTPS `/healthz` и рендер установленного
dashboard с declaration-before-use. Полный внешний healthcheck после изменения — PASS.
Canonical и public прошли по **1203 теста, OK (skipped=3)**. GitHub по-прежнему не
изменялся.
