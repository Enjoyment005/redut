# Редут 1.13.1 — усиленный DNS Rescue

Дата: 2026-09-06

## Итог

Это исправленный выпуск DNS Rescue после независимого security-аудита 1.13.0. Режим
остаётся дополнительным последним шагом: обновление не включает перехват DNS и не меняет
маршруты боевых узлов. По умолчанию стоят `mode=disabled`, `owner_approved=false` и
`automatic_ready=false`.

## Что исправлено

- automatic eligibility появляется только после terminal exhaustion штатной лестницы;
  rate-limit, пауза автоматики и ручной `EMERGENCY` её не дают;
- isolated manual, node-wide manual и node-wide automatic разделены контрактами состояния;
  scoped и global трафик используют разные owned NAT/INPUT chains;
- high-port listener привязан только к адресу `wg0`; INPUT ACL разрешает loopback и точный
  WireGuard scope, остальное отбрасывает; кроме SYN connlimit применён отдельный per-source
  packet rate-limit для TCP/53, а preflight-файлы создаёт root в отдельном каталоге, куда
  сервисный пользователь не может подменить путь;
- activation проверяет UDP и TCP backend, exact WG `/32` ownership, emergency route и
  наблюдаемый рост счётчика реального `wg0 -> PREROUTING -> redirect`;
- DNS parser и внешний runner v3 используют новый одноразовый QNAME в контролируемой зоне,
  принимают только A RR с точным owner/IPv4 и TTL 0..300; журнал не хранит QNAME, адрес
  клиента, endpoint или произвольный текст ошибок;
- внешний root-owned runner закреплён SHA256, связывает каждый UDP/TCP/application proof с
  challenge, WireGuard generation, QNAME и ожидаемым ответом, а два IP/TLS control отличают
  DNS-отказ от общей потери связи;
- bounded candidate series и runtime failover перебирают разные операторы и `proxy/direct`;
  successor сначала проходит UDP/TCP/application proof на отдельном exact-peer high-port
  sidecar в фиксированном transient systemd unit с `RuntimeMaxSec=45s`, и лишь затем меняется
  live resolver; панель получает только schema-validated transport booleans без raw stdout;
  общий режим не выключается по TTL, isolated canary имеет жёсткое время жизни и снимается
  сразу при уходе автомата из `OK`; deadline каждой операции ограничен `not_after` кандидата
  и перепроверяется перед каждым новым dial/probe/start/commit;
- fail-open сначала удаляет и проверяет redirect, затем останавливает listener. При неполной
  очистке listener сохраняется, состояние становится `recovering`; upgrade также распознаёт
  и безопасно снимает legacy chains выпуска 1.13.0;
- все read/reserve/mutate шаги выполняются под общим `/run/vpn-agent.lock`; выход из любого
  `EMERGENCY` координируется с DNS saga; self-update передаёт тот же открытый lock fd детям;
- ручной node-wide DNS Rescue связан с durable id конкретной ручной EMERGENCY-сессии;
  isolated canary разрешён только из нормального незамороженного состояния;
- systemd timer каждые 5 секунд сверяет SQLite с firewall/service/backend и чинит незавершённые
  операции после сбоя; node-wide rescue после reboot восстанавливается отдельной durable
  continuation saga с новым boot id, повторным route/WG/client proof и максимум тремя раундами;
  continuation привязана к тому же incident/manual reference, а isolated canary после reboot
  очищается и автоматически не восстанавливается; неизвестный boot/route/WG/service state
  обрабатывается как tri-state, а перед bounded fail-open teardown node-wide режима сохраняется
  точный resume-дескриптор;
- добавление/удаление WireGuard-клиентов использует тот же network lock и crash-safe forward/
  rollback journal; операция запрещена, пока DNS Rescue владеет cohort, а delete допускается
  только для ровно одного IPv4 `/32` внутри VPN-подсети. Конфиги с PrivateKey/PSK пишутся через
  `0600` temp, `fsync`, atomic replace и проверку владельца/типа;
- таймаут self-update завершает всю process group, поэтому дочерний процесс не может унаследовать
  lock и продолжить изменение после того, как родитель сообщил об откате;
- автоматический gate требует два оператора, два endpoint, `proxy+direct`, свежие сроки
  кандидатов, canary/clock/firewall/resource/leak-policy evidence, rollback drill и профили
  `wg-ip`/`external-ip`;
- установленный sing-box 1.11.7 теперь проверяется не только по строке версии, но и по
  закреплённому SHA256 самого бинарника;
- RU allowlist использует общий lock, pinned inputs, candidate/LKG и durable pending marker
  для восстановления незавершённого поколения; rollback восстанавливает файлы/ipset,
  выполняет проверяемый полный restart старого dnsmasq и очищает dynamic domain set до удаления
  marker; закреплённые SHA256 сверены с immutable upstream commit, а валидатор принимает корректные
  IDNA A-label (`xn--`) и по-прежнему отклоняет инъекции/невалидные DNS labels;
- install/setup/deploy больше не подменяют canonical watchdog второй реализацией. Watchdog не
  пишет routes и не рестартует sing-box сам, а передаёт решение `vpn-agent` под общим lock;
  `ExecStartPost` только ставит отложенный reconcile после выхода unit из `activating`;
- `/setup` больше не является first-visitor TOFU: установщик печатает случайный одноразовый
  bootstrap-код только в SSH, на диске остаётся SHA256 в root:0600 с TTL 24 часа; claim создаёт
  одну 30-минутную setup-сессию, второй claim инвалидирует первую, finish гасит код;
- recovery consume, provider-key writes и CLI reset администратора объединены одним
  межпроцессным lock и durable atomic writer. Один recovery-код имеет ровно одного победителя
  при параллельных запросах;
- HTTP reader требует единственный корректный `Content-Length`, запрещает неоднозначный framing,
  ограничивает POST 64 KiB (login 8 KiB), число worker threads — 32, одновременный scrypt — 4;
  systemd ограничивает память/tasks/file descriptors панели;
- self-update сверяет точные WireGuard public keys и AllowedIPs, forwarding/policy route,
  normal/emergency intent и DNS runtime. Активное/неочищенное поколение DNS Rescue блокирует
  update, а живые units без рабочего data plane больше не дают успешный commit;
- очистка узла ограничена Redut-owned временными артефактами и bounded хвостом собственных логов;
  она больше не удаляет чужие `/tmp`/`/opt`, `known_hosts`, journald, login/package history,
  dmesg и failed-unit evidence;
- исторический decision payload имеет явные лимиты 64 KiB/depth/nodes и object schema;
  невалидная запись отдаётся как `decision=null` с `decision_invalid=true`;
- DNS API сведён к одному GET и одному POST handler, status читает DNS-состояние один раз.

## Границы

Контролируется только IPv4 UDP/TCP DNS на порту 53, пришедший через `wg0`. IPv6,
application DoH/DoH3/DoT и клиенты вне WireGuard показываются как unmanaged. TLS DoH
проверяет сертификат для literal-IP endpoint без зависимости от bootstrap DNS.

Live Linux/WireGuard canary и внешний runner в локальную сборку не входят. Transient
systemd sidecar и reboot-restore проверены unit/integration-моделями, но не целевой Debian.
Поэтому это
локальный безопасно инертный кандидат, пока не опубликованный в GitHub. Включать automatic
mode можно только после отдельной проверки на тестовом peer, controlled wildcard zone,
проверки часов/iptables/conntrack/ресурсных SLO и фиксации свежих evidence в конфигурации.

Per-peer QPS/burst, TCP packet-rate и TCP SYN connlimit ограничены firewall, однако точный глобальный лимит
outstanding запросов и TCP idle timeout пока не доказаны на живой Debian. OUTPUT/FORWARD
53/853, IPv6 и application DoH/DoH3/DoT остаются вне режима и не должны называться
покрытыми. Это эксплуатационные стоп-гейты, а не скрытые обещания реализации.

Локальные проверки кандидата: **993 unit/integration тестов**; Python compile; JSON и
shell syntax; официальный `sing-box 1.11.7 check` для четырёх gateway-конфигураций;
детерминированные UDP/TCP parser/runner tests. GitHub commit/tag/push не выполнялись.
