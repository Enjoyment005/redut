# Контракт внешнего DNS canary runner (v4)

Дата: 8 сентября 2026 года. Код v4 подготовлен локально; физическая приёмка ещё обязательна.
Runner — внешний компонент, его исполняемый файл и ключи в репозиторий не входят.
`runner_contract_version=4` не заменяет проверку SHA256 и живое доказательство.
Версия 3 временно допускается в observe/manual; automatic activation требует v4.

## Доверенная установка

- Путь `/usr/local/libexec/redut-dns-canary`, обычный executable, root-owned, без group/world write.
- SHA256 совпадает с `dns_rescue.canary_runner_sha256`; окружение очищено.
- Controlled wildcard `canary_qname_suffix` возвращает только `canary_expected_ipv4`, TTL 0–30 секунд.
- `semantic_sentinels`: одно или два отдельно утверждённых стабильных имени; по умолчанию список пуст.
- Все IPv4 /32 peers сопоставляются с root-owned `/etc/wireguard/clients/*.conf`. Неполный inventory
  или смешанный/неподдерживаемый DNS-профиль закрывает node-wide activation.
- Runner проверяет ровно запрошенные реально присутствующие profile classes на exact canary peer.
  `wg-ip` использует DNS=адрес wg0; `external-ip` — сохранённый внешний IPv4 resolver.

## CLI и пределы

Общие аргументы прежней версии сохраняются:

```text
--mode candidate-preflight|rescue-roundtrip|primary-recovery|causal-round
--scope all|peer:<IPv4>
--route-generation <WireGuard scope digest>
--challenge <32 lowercase hex>
--qname <challenge>.<owned suffix>
--expected-ipv4 <owned wildcard IPv4>
--profiles wg-ip,external-ip
--transports udp,tcp
--contract-version 4
--operation-timeout-ms 2000
```

Для preflight/roundtrip добавляются `--listen` и `--port`. Для primary/causal —
`--dns <primary IPv4> --port 53`. Causal также получает `--candidate-id`,
`--candidate-operator`, `--candidate-transport` и `--sentinels` (имена через запятую).
Это только идентификаторы безопасных слотов из конфигурации: runner обязан сверить их с
root-owned установленной конфигурацией, включая endpoint, transport, TLS identity и expiry.
Proxy transport использует действующий SOCKS outbound, direct — прямой путь. Все DoH
проверки аутентифицируют сертификат; bootstrap по plain DNS и fallback на HTTP запрещены.

В каждом causal round UDP, TCP, application и выбранный DoH используют **один QNAME**.
Следующий round получает новый challenge. Все независимые сетевые операции внутри round
выполняются параллельно, каждая ограничена 2 секундами. Coordinator запускает раунды примерно
на 0/4/8 секунде с jitter 0–500 мс; deadline всей серии — 15 секунд, runner round — до 2,5 секунды.
Нельзя выполнять серию из последовательных двухсекундных ожиданий внутри runner.

Вывод: один JSON до 32768 байт для v4 (v3 — 4096); duplicate keys, NaN, лишние поля,
неполный report, неправильные challenge/generation/profile означают UNKNOWN.
После каждого раунда coordinator повторно проверяет WG identity, exact peer, profile inventory
и отдельный digest middleman routes/IP rules. Эти проверки не заменяются сообщением runner.

## JSON v4

Верхний уровень: ровно `version`, `challenge`, `route_generation`, `query`, `profiles`.
`version` — целое 4. `query` — ровно `{qname, type: "A", expected_ipv4}`.
Набор ключей `profiles` точно совпадает с CLI.

Каждый результат DNS (UDP, TCP, application, secure) имеет ровно эти поля:

```json
{
  "status": "PASS",
  "reason": "ok",
  "qname": "0123456789abcdef0123456789abcdef.canary.example.net",
  "rcode": 0,
  "answers": [
    {"owner": "0123456789abcdef0123456789abcdef.canary.example.net",
     "type": "A", "value": "192.0.2.53", "ttl": 30}
  ],
  "latency_ms": 25
}
```

`status`: PASS, FAIL, UNKNOWN. Причины: `ok`, `nxdomain`, `nodata`, `servfail`, `refused`,
`timeout`, `wrong_rrset`, `control_failed`, `runner_error`. RCODE должен соответствовать причине.
Для timeout/runner_error RCODE=null; NXDOMAIN/NODATA/timeout/runner_error не имеют A answers.
`latency_ms` — конечное число 0–2000. UNKNOWN всегда `runner_error`, RCODE=null, answers=[].
Только завершённый запрос с неправильным ответом или исчерпанным сетевым timeout даёт FAIL.
Недоступность runner/namespace/inspection, ошибка запуска или неполные данные дают UNKNOWN.

Для controlled canary PASS требует один точный A, TTL 0–30, совпадение question/owner/type/ID,
NOERROR, отсутствие AAAA/CNAME/DNAME, посторонних записей, truncation и trailing data.
Runner обязан проверить wire message до выдачи PASS; `answers` включает полный ответ,
а не только подходящий A. Ответ «ожидаемый A + посторонний A» — FAIL/wrong_rrset.

В каждом profile обязательны:

- `dns`: объект ровно с `udp`, `tcp`;
- `application_dns`: DNS result от штатного application resolver;
- `controls`: ровно два IP/TLS/SNI control, без зависимости от проверяемого DNS.

```json
[
  {"id":"control-a","failure_domain":"cloudflare","status":"PASS","ip_tls":true,"hostname":true},
  {"id":"control-b","failure_domain":"google","status":"PASS","ip_tls":true,"hostname":true}
]
```

Runner использует отдельно утверждённые IP/SNI этих операторов, проверяет TLS и hostname.
Произвольная смена failure_domain при сохранении ID не допускается.

Только в causal-round profile дополнительно содержит:

- `secure`: ровно `{slot, operator, transport, dns}` выбранного Rescue-кандидата;
- `sentinels`: объект с точным набором утверждённых имён. Для каждого имени —
  `{dns: {udp, tcp}, application_dns, secure: {cloudflare, google}}`.

Каждый secure sentinel result относится к тому же sentinel QNAME. Оба независимых оператора
должны подтвердить NOERROR/существование имени. CDN-IP между ними могут различаться;
DNSSEC validation применяется, если зона и runner её поддерживают. Согласованный NXDOMAIN
у primary и secure, disagreement или UNKNOWN не доказывает подмену.

## Решения и жизненный цикл

Automatic: 3/3 успешных controls и выбранный candidate; согласующийся application/primary fault
в 2/3 rounds, обязательно в последнем, для каждого присутствующего profile class. Рабочий TCP
не запрещает Rescue при ложном UDP NXDOMAIN/wrong RRset/NODATA и таком же application fault.
Одна серия резервируется в SQLite до первой внешней пробы и не повторяется в том же incident.
Exact-peer preflight обязателен перед global redirect. Readiness/candidate expiry ограничивают
весь cutover; profile/route snapshot повторно сверяется перед ним и перед commit.

Active: local backend каждые 5 секунд, три FAIL; client path каждые 60 секунд, два FAIL.
UNKNOWN не увеличивает failures, не разрешает cutover/return и сохраняет listener. После 15 минут
непрерывной неизвестности формируется критическое событие и предупреждение панели.
Minimum dwell — 300 секунд по monotonic clock. После него нужны три primary PASS через 60 секунд.
FAIL сбрасывает серию, UNKNOWN приостанавливает её. Ручной EMERGENCY автоматически не снимается.

Обычное отключение — journaled saga: снять NAT, доказать detachment, удалить DNS conntrack
только затронутых peers, новым QNAME проверить primary, затем остановить listener и снять ACL.
Если primary не доказан, вернуть прежнюю рабочую generation и оставить EMERGENCY.
При kill до окончания proof reconcile восстанавливает прежнюю generation при совпадении
scope/boot и работающем listener. Proven inactive listener, смена boot/scope и истечение
isolated TTL остаются аварийными основаниями fail-open cleanup без возврата к старому scope.

Удаление stale global NAT из isolated rollback требует отдельной journaled global-drain
операции и degraded-события; listener сохраняется до завершения drain. Скрытый global drain запрещён.

Failover остаётся через существующий sidecar preflight и перезапуск live listener. Blue-green
cutover добавляется только после физического измерения недопустимого blackout. Локальные
моделируемые циклы не доказывают WAN ACL, conntrack, Android cache, reboot или SLO.

## Privacy и эксплуатационные gates

SQLite и UI получают только агрегированные status/reason/latency и ID операций. QNAME,
RR payload, upstream endpoint, public/private WG keys не публикуются. Полный runner report
не журналируется. IPv6 и application DoH/DoH3/DoT отображаются как unmanaged.

Automatic остаётся закрыт без digest-pinned v4 runner, controlled zone, утверждённых sentinel,
актуального inventory, свежего полного evidence pack/readiness_not_after, rollback drill,
физических нагрузочных/reboot/conntrack проверок и отдельного разрешения владельца.
