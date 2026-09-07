# Контракт внешнего DNS canary runner (v3)

Статус: обязательный внешний компонент DNS Rescue 1.13.1. Сам runner и его ключи в
репозиторий не входят. Пока он не установлен и не принят на живом тестовом WireGuard peer,
активация DNS Rescue должна оставаться закрытой.

## Доверенная установка

- фиксированный путь: `/usr/local/libexec/redut-dns-canary`;
- обычный executable-файл, владелец `root`, без group/world write;
- SHA256 файла точно совпадает с `dns_rescue.canary_runner_sha256`;
- runner запускается с очищенным окружением, ограниченным временем и выводом не более 4096 байт;
- `canary_peer_ipv4` принадлежит ровно одному ожидаемому WireGuard peer `/32`.

## Controlled canary

Владелец задаёт контролируемую authoritative-зону и wildcard `A`:

- `canary_qname_suffix` — suffix зоны, например `canary.example.net`;
- `canary_expected_ipv4` — точный IPv4 wildcard-ответ;
- TTL ответа — целое число от 0 до 300 секунд.

Redut создаёт новый 128-битный challenge для каждого proof и передаёт QNAME
`<challenge>.<canary_qname_suffix>`. Такой QNAME нельзя брать из прежнего resolver/OS cache.
QNAME, payload и адрес peer не пишутся в SQLite, события или публичный status.

## CLI

Обязательные аргументы:

```text
--mode candidate-preflight|rescue-roundtrip|primary-failure|primary-recovery
--scope all|peer:<IPv4>
--route-generation <opaque WireGuard inventory digest>
--challenge <32 lowercase hex>
--qname <challenge>.<configured suffix>
--expected-ipv4 <configured IPv4>
--profiles wg-ip,external-ip
--transports udp,tcp
```

Для `candidate-preflight` и `rescue-roundtrip` также передаются `--listen` и `--port`.
При runtime failover `candidate-preflight` идёт на отдельный `preflight_port`, а не на live
listener; transient systemd unit и exact-peer ACL должны быть полностью сняты до cutover.
Для `primary-failure` и `primary-recovery` — `--dns` и `--port 53`. Runner не принимает
от Redut произвольный shell, URL, payload или адрес клиента.

## Единственный допустимый JSON-ответ

```json
{
  "version": 3,
  "challenge": "0123456789abcdef0123456789abcdef",
  "route_generation": "opaque-generation",
  "query": {
    "qname": "0123456789abcdef0123456789abcdef.canary.example.net",
    "type": "A",
    "expected_ipv4": "192.0.2.53"
  },
  "profiles": {
    "wg-ip": {
      "dns": {
        "udp": {"ok": true, "qname": "0123456789abcdef0123456789abcdef.canary.example.net", "answer_ipv4": "192.0.2.53", "ttl": 30},
        "tcp": {"ok": true, "qname": "0123456789abcdef0123456789abcdef.canary.example.net", "answer_ipv4": "192.0.2.53", "ttl": 30}
      },
      "application_dns": {"ok": true, "qname": "0123456789abcdef0123456789abcdef.canary.example.net", "answer_ipv4": "192.0.2.53", "ttl": 30},
      "controls": [
        {"id": "control-a", "ip_tls": true, "hostname": true},
        {"id": "control-b", "ip_tls": true, "hostname": true}
      ]
    }
  }
}
```

Набор `profiles` должен точно совпасть с запросом. Для каждого профиля обязательны UDP,
TCP, прикладная DNS-проверка и два разных IP/TLS+SNI control. В `primary-failure` поля DNS
`ok` должны быть `false`, при этом у обоих controls `ip_tls` и `hostname` остаются `true`;
`answer_ipv4` и `ttl` равны `null`. В остальных режимах DNS должны быть `true`, owner QNAME и A-ответ —
точными, TTL — в диапазоне. Любое лишнее/пропавшее доказательство, несовпадение challenge,
QNAME, generation, profile, ответа или превышение лимита означает `proof=false`.

## Последовательность

Node-wide активация сначала ставит ACL и redirect только для exact canary peer, требует
валидный v3 report и рост обоих UDP/TCP counters, снимает scoped redirect и дренирует
conntrack. Только затем она повторно проверяет intent/route/WireGuard identity и включает
global redirect. Возврат на primary проверяется через отдельную временную RETURN-chain
только для exact peer; chain всегда нейтрализуется и удаляется до следующего решения.
Runtime failover сначала поднимает successor в фиксированном transient systemd control group
на отдельном high port, доступном только одному exact peer. После полного v3 proof sidecar
останавливается и его ACL/config удаляются; лишь затем атомарно заменяется конфигурация live
resolver при сохранённом NAT. После падения координатора reconcile сначала доказывает смерть
всей sidecar control group и только потом снимает её guard. Сам transient unit имеет независимый
`RuntimeMaxSec=45s`, поэтому не может жить бесконечно при гибели координатора.

После reboot автоматически реконструируется только node-wide rescue того же incident ID либо
той же ручной EMERGENCY-сессии. Компенсация ограничена тремя durable раундами. Isolated canary
не переносится между boot: scoped redirect/listener очищаются, а оператор открывает новую
сессию с новым monotonic TTL.

## Стоп-гейты эксплуатации

Automatic mode не готов к включению, пока нет одновременно: digest-pinned runner; живого
peer для обоих profile classes; controlled wildcard zone; синхронизированных часов; свежих
candidate/readiness evidence; успешного rollback drill; проверки iptables/hashlimit/
connlimit и conntrack на целевой Debian; измеренных CPU/RAM/QPS/SLO; принятых IPv4 leak-policy
границ. В конфигурации это фиксируют `canary_evidence_id`, `clock_evidence_id`,
`firewall_drill_evidence_id`, `resource_slo_evidence_id`, `leak_policy_evidence_id` и общий
`readiness_not_after`. Текущая защита задаёт
per-peer QPS/burst и TCP SYN connlimit, но не заявляет точный глобальный лимит outstanding
запросов или TCP idle timeout. IPv6, application DoH/DoH3/DoT и server OUTPUT/FORWARD 53/853
этот режим не перехватывает; интерфейс обязан показывать их как unmanaged.
