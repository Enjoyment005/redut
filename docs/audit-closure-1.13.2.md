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
