# План режима `DNS_RESCUE` для Redut

Исходный аудит: 2026-09-01, локальная версия `1.12.3`. Редакция режима: 2026-09-06.

Статус: **релиз 1.13.2 после повторного adversarial security review; live-canary не
выполнен**. Без digest-pinned внешнего
runner v3, controlled wildcard zone, живого exact WireGuard peer и свежих canary/rollback
evidence конфигурация принудительно оставляет `automatic_last_resort` закрытым. Установка
кода сама не меняет DNS, маршруты или режим на боевых узлах; manual canary и production
требуют отдельного подтверждения владельца.

Локально закрыты архитектурные стоп-дефекты повторного review: раздельные global/scoped
chains, exact-peer preflight, failover через отдельный transient sidecar до live cutover,
bounded node-wide reboot/exit continuation, route/WG/boot/manual/incident identity, строгий runner v3,
fail-open cleanup и полный evidence gate. Не закрыты эксплуатационные доказательства на
целевой Debian: живой runner/controlled zone/peer, iptables+conntrack drill, reboot drill,
clock/CA, ресурсные SLO и принятая IPv4 leak-policy. Поэтому режим остаётся выключенным.

Основание: техническая записка `DNS_TSPU_technical_notes.docx` о перехвате открытых
DNS-запросов, текущая архитектура Redut и проверка локальных файлов проекта.

## 1. Цель и место режима в Redut

Реализовать DNS-устойчивость как отдельный режим Redut — `DNS_RESCUE` («Аварийный DNS»),
а не как обязательную замену штатного DNS. В нормальной работе режим подготовлен, но не
управляет трафиком. Redut пробует его только после того, как штатная лестница восстановления
и прямой `EMERGENCY` не вернули рабочий доступ.

Режим должен:

1. не менять штатный DNS/data-plane до подтверждённого аварийного входа;
2. после исчерпания обычного recovery выполнить ограниченную проверку альтернативных
   DNS-путей и включить только тот, который заранее доказал работоспособность;
3. сохранять прямой `EMERGENCY`, если аварийный DNS тоже не помог;
4. отличать DNS-проблему от отказа proxy, sing-box, WAN и самого сервиса;
5. не покупать и не ротировать прокси из-за одного DNS-сигнала;
6. управлять обычным UDP/TCP DNS и честно показывать границы контроля для IPv6,
   application DoH/DoH3 и клиентского кэша;
7. автоматически возвращаться в штатный режим только после доказанного восстановления;
8. внедряться поэтапно: observe-only -> ручной canary -> automatic last resort.

Ключевой принцип: **Redut должен продолжать давать связь**. `DNS_RESCUE` — дополнительная
попытка после отказа обычных механизмов, а не новый обязательный путь. Если кандидат режима
не проходит probe, правила не применяются: Redut остаётся в `EMERGENCY`, показывает
`Аварийный DNS не помог / UNAVAILABLE` и не создаёт бесконечный цикл переключений.

## 2. Что есть сейчас

### 2.1. Сильная база

- Клиентский IPv4-трафик идёт через WireGuard и таблицу `middleman` в `tun0`.
- sing-box уже содержит DNS-контур: DoH endpoint, `detour: socks-out` и обработку DNS
  отдельным outbound.
- На узле без dnsmasq клиент использует `DNS = 1.1.1.1`; этот трафик в штатном режиме
  попадает в общий туннельный путь.
- Health quorum уже отделяет отказ одного сайта или DNS от подтверждённой смерти прокси.
- `EMERGENCY` уже обеспечивает прямую связь вместо чёрной дыры.
- Применение proxy-конфигурации имеет probe, check, backup, verify и rollback.

### 2.2. Подтверждённые разрывы

1. При включённом dnsmasq его upstream задан как обычные `1.1.1.1` и `8.8.8.8`.
   Запросы процесса сервера не проходят через клиентское правило `PREROUTING`, поэтому
   защищённый data plane не означает автоматически защищённый upstream dnsmasq.
2. В `EMERGENCY` клиентский DNS закономерно выходит через прямой WAN и может подвергаться
   перехвату или подмене.
3. Клиентские профили содержат только `AllowedIPs = 0.0.0.0/0`; IPv6 не управляется
   общим туннельным инвариантом.
4. Текущий health-контур видит отдельную ошибку DNS-разрешения имени, но не проверяет
   семантическую целостность ответа: ложный NXDOMAIN, необычные flags/authority, различие
   direct UDP/TCP и удалённого защищённого ответа.
5. dnsmasq одновременно выполняет резолвинг и наполняет `ru_whitelist`. Простая замена
   всех upstream на зарубежный resolver способна ухудшить геолокацию CDN и прямой доступ
   к российским сервисам.
6. Ложный NXDOMAIN может пережить восстановление канала в кэше ОС, браузера или dnsmasq.

### 2.3. P0-блокеры, найденные security review

1. В canonical и публичном шаблонах sing-box присутствуют непустые значения upstream
   server/user/password, не похожие на явные placeholders. Их действительность не
   проверялась, значения нельзя раскрывать. До любой новой публикации требуется отдельный
   secret preflight с разрешением владельца; подтверждённые реальные credentials означают
   остановку публикации, revoke/rotate и отдельный incident-план очистки canonical/public/
   history. Эту операцию нельзя смешивать с DNS rollout.
2. Weekly updater RU allowlist доверяет tip внешнего Git-репозитория, разбирает все подходящие
   текстовые файлы и активирует найденные IP/CIDR после слабого sanity check. Так как
   `ru_whitelist_net RETURN` стоит перед общей маркировкой в proxy, вредоносный или ошибочный
   широкий prefix способен перевести значительную часть или весь клиентский трафик в direct.
   До hardened split этот источник считается недоверенной data supply chain.
3. Текущий boot-скрипт очищает built-in `mangle PREROUTING`, а updater после изменения списка
   вызывает весь boot-скрипт. Это нарушает единоличное владение правилами и способно
   конфликтовать с `EMERGENCY`, другими firewall-потребителями и параллельным apply.

## 3. Модель угроз и границы доверия

### 3.1. Защищаемые свойства

- доступность резолвинга и прикладного трафика;
- конфиденциальность QNAME на локальном WAN;
- целостность DNS-ответа в пределах заявленной модели доверия;
- соответствие выбранного DNS-view фактическому data-plane;
- невозможность превратить DNS-сбой в proxy rotation, покупку или снятие `MANUAL`;
- правдивость `desired/effective` состояния в UI и журнале;
- целостность dynamic route claims, firewall policy и источника RU allowlist;
- отсутствие открытого resolver/amplifier на WAN и bounded потребление ресурсов.

### 3.2. Противники

1. Сетевой оператор/TSPU на WAN: может drop/DNAT/inject/reorder/throttle, блокировать
   endpoint и провоцировать fallback.
2. Вредоносный или скомпрометированный resolver: может вернуть policy answer, ложный
   NXDOMAIN, private/control IP или специально сконструированную alias chain.
3. Upstream proxy/provider: может выборочно блокировать соединения и создавать общий
   failure domain, даже если не способен прочитать корректно защищённый DoH payload.
4. Скомпрометированный WireGuard-клиент: может flood listener, исчерпывать cache/concurrency,
   инициировать rebinding и пытаться наполнить общий direct set выгодными адресами.
5. Отравленный внешний RU allowlist/update source: может добавить широкий prefix, private
   range, endpoint управления или домен верхнего уровня.
6. Локальный непривилегированный процесс: может пытаться использовать listener/fallback
   вне разрешённого пути либо создавать retry/log storm.

### 3.3. Trust anchors и границы гарантии

- WireGuard-ключи и root узла;
- системный CA store, корректное системное время и проверенная поставка бинарников;
- явно выбранные resolver operators и их TLS identity;
- versioned/pinned allowlist snapshot, прошедший quarantine и policy validation;
- operation journal, checksums и фактическая проверка listener/firewall/route после reboot.

DoH защищает канал до аутентифицированного resolver, но сам по себе не доказывает
происхождение DNS-данных. Без локальной DNSSEC validation resolver остаётся доверенной
стороной. Компрометация root узла находится за границей этого плана. Произвольный DoH на
443 нельзя полностью перехватить без TLS interception; Redut этого не делает.

### 3.4. Цели атакующего

- принудительно вызвать `dns_rescue_phase=active_direct` и раскрыть реальный egress;
- внести управляемый адрес или широкий prefix в direct set;
- заставить UI показать green при fail-open, stale evidence или частичном IPv6 coverage;
- вызвать secure/direct flapping и закрепить poisoned negative cache;
- использовать listener для amplification или исчерпания CPU/RAM/file descriptors;
- создать гонку installer/update/updater/watchdog/panel и оставить неизвестное состояние.

## 4. Неприкосновенные инварианты

1. `EMERGENCY` продолжает давать прямой IPv4-интернет; `DNS_RESCUE` накладывается на него
   только после успешного probe и не превращает аварию в fail-closed для устройства.
2. DNS-only anomaly не является `proxy_fault` и не разрешает ротацию, покупку или
   снятие `MANUAL`.
3. Неизвестность не считается перехватом. Для вывода нужны свежие независимые сигналы.
4. До аварийного trigger штатный DNS и data-plane не меняются. Внутри активного
   `DNS_RESCUE` запрещены тихий downgrade и непроверенный direct fallback.
5. Прямой resolver разрешён только как явно помеченный кандидат rescue/local-RU или как
   уже существующий аварийный путь.
6. После выхода из деградированного режима server-side negative cache/generation очищается
   до secure-статуса; UI сохраняет `recovery pending` до истечения ранее выданного client TTL.
7. Ни в SQLite, ни в события, ни в панель не записываются пользовательские QNAME.
   Допустимы только ID контрольного запроса, агрегаты и заранее известные canary-домены.
8. Нельзя одновременно выкатывать DNS-архитектуру и новую major/minor-схему sing-box:
   сначала один риск, приёмка и откат, затем следующий.
9. Публичная папка `Гитхаб/` не редактируется руками; она пересобирается штатным builder
   только после локальной и canary-приёмки.
10. `PROTECTED` означает защищённый транспорт до аутентифицированного resolver, а не
    доказанную DNSSEC-подлинность origin data.
11. Ни external allowlist, ни один DNS-ответ не являются самостоятельным разрешением
    изменить routing policy без policy validation и provenance.
12. Installer, self-update, updater, watchdog и panel не могут быть независимыми writers
    одного DNS/firewall/route состояния.

## 5. Целевая архитектура режима `DNS_RESCUE`

### 5.1. Два DNS-view внутри режима

Эти view не обязаны заменять штатный DNS Redut. Они становятся активными только при
`automat_state=EMERGENCY` и `dns_rescue_phase=active_*`; вне режима работают лишь probes.
В первом P0-релизе
`LOCAL_RU` остаётся `observe_only` и не создаёт direct claims: rescue использует только
проверенный `REMOTE_SECURE`. Split включается позднее отдельным P1-гейтом.

#### `LOCAL_RU`

- Только домены явного российского allowlist.
- Резолвинг через локальный/региональный resolver для правильной геолокации CDN.
- Сам факт DNS-ответа **не** даёт права добавить адрес в `ru_whitelist`: нужен валидный
  route claim с provenance, допустимой CNAME-цепочкой, TTL и поколением policy.
- В set попадают только финальные A/AAAA после проверки адресных диапазонов; private,
  loopback, link-local, multicast, documentation, control-plane и слишком широкие сети
  запрещены.
- Ответы этого view не считаются доверенным источником для default/protected-доменов.
- При отказе local resolver допускается управляемый fallback через удалённый resolver,
  но результат помечается degraded и **не создаёт direct route claim**, пока отдельная
  route-validation не докажет допустимость адреса для degraded routing policy.

#### `REMOTE_SECURE`

- Все остальные rescue-запросы.
- Первый кандидат — аутентифицированный DoH через ещё работоспособный `socks-out`/туннель;
  второй — тот же класс DoH напрямую через WAN, если proxy-path не работает, но HTTPS-доступ
  сохранился. Direct DoH всегда отображается как degraded rescue, а не штатная защита.
- Для каждого кандидата обязательны hostname/SNI, системная CA-цепочка и корректное время;
  `insecure`, silent downgrade и redirect на
  другой origin/scheme запрещены.
- Минимум два endpoint разных операторов/trust-domain. Общий `socks-out` остаётся общей
  точкой отказа и не считается resolver diversity.
- Внутри одного transport сначала перебираются resolver operators; переход
  `doh_via_proxy -> doh_direct_wan` разрешён только после отказа всех готовых operators на
  текущем transport. Смена transport не изображает resolver diversity.
- Bootstrap не зависит от перехватываемого DNS: допустим endpoint по IP только при
  валидной TLS identity либо версионированная статическая адресация с expiry/rotation.
- Нет открытого fallback на UDP/TCP 53, пока канал считается штатным.
- Ответы этого view не смешиваются с прямым/аварийным negative cache.

### 5.2. Точка входа и неактивное состояние

Компоненты и dedicated firewall chain заранее установлены как неактивная capability. Вне
режима существующий dnsmasq/listener остаётся владельцем WG-IP, rescue listener доступен
только на loopback для probes либо остановлен, а chain не перехватывает клиентский DNS.
Только успешный кандидат проходит activation saga; её последним атомарным шагом меняется
dedicated chain. Для профилей с WG-IP переключается backend существующей точки входа, а
старые профили с `DNS=1.1.1.1` требуют доказанного server-side interception.

```text
NORMAL/RECOVERY/EMERGENCY -> штатный DNS-путь без изменений
                                     |
                          всё штатное recovery исчерпано
                                     v
                          dns_rescue_phase=probing
                                     |
                              кандидат успешен
                                     v
клиент -> rescue chain -> WG DNS listener
                              |
                              +-- P0: REMOTE_SECURE
                              |       |-- DoH через живой proxy/tun
                              |       `-- DoH напрямую через WAN (degraded)
                              |
                              `-- P1 отдельно: LOCAL_RU -> validated direct claim
```

Текущий шаблон sing-box содержит TUN inbound, но это само по себе не доказывает наличие
UDP/TCP DNS-listener для WireGuard-клиентов. ADR обязан лабораторно подтвердить полный путь:
`WG client -> UDP/TCP 53 -> listener -> view -> upstream -> выбранный data-plane`.

На архитектурном spike без заранее назначенного победителя сравнить два варианта:

1. sing-box `1.11.7` как DNS gateway — только если доказан реальный ingress, TCP fallback,
   bind/ACL и жизненный цикл без неявной зависимости от deprecated DNS outbound;
2. dnsmasq как фронтенд на WG-IP + минимальный loopback stub для защищённого upstream —
   после security, resource, packaging и upgrade-аудита.

Выбор варианта фиксируется коротким ADR до реализации. Обязательно проверить поведение
на закреплённой версии sing-box `1.11.7`: текущий special DNS outbound имеет известную
границу совместимости с будущими версиями, поэтому новый контур нельзя строить на
непроверенном предположении о последующем апгрейде sing-box.

Дополнительный гейт: установщик сейчас загружает sing-box без проверки checksum/signature.
До нового DNS-контура источник бинарника, версия, хэш и процедура обновления должны стать
проверяемыми и fail-closed.

### 5.3. Ортогональная фаза внутри `EMERGENCY`

`DNS_RESCUE` — отдельный пользовательский режим, но **не** новое значение существующего
`automat_state`. На всём протяжении rescue сохраняются `automat_state=EMERGENCY`, прямой
маршрут и `/run/vpn-agent-emergency`. Отдельно хранится runtime-поле:

`dns_rescue_phase = idle | probing | active_proxy | active_direct | failed | recovering`.

Это сохраняет совместимость с текущими watchdog, reboot/reinstall recovery и sticky
`emergency_manual`. `failed` — результат попытки внутри `EMERGENCY`, а не верхнеуровневое
состояние автомата.

```text
automat_state: NORMAL -> штатный RECOVERY/FAILOVER -> EMERGENCY
                                                     |
                                dns_rescue_phase: idle
                                                     |
                                          доступ не восстановлен
                                                     v
                                                 probing
                                               /         \
                                      probe success     probes failed
                                           v                 v
                               active_proxy/direct          failed
                                           |
                               normal path independently proven
                                           v
                                      recovering -> idle
                                           |
                           единый coordinated exit из EMERGENCY
                                           v
                                         NORMAL
```

| `automat_state` / `dns_rescue_phase` | DNS-действие | Отображение | Следующий шаг |
|---|---|---|---|
| `NORMAL` / `idle` | штатный путь без изменений | обычный статус Redut | ничего |
| `NORMAL` / `idle` + manual test session | DNS меняется только для test peer | `Тест аварийного DNS` | удалить scoped rules и вернуть snapshot |
| штатный recovery / `idle` | только наблюдение | штатное восстановление | выполнить существующую лестницу |
| `EMERGENCY` / `idle` и доступ работает | существующий direct DNS | `Интернет напрямую, DNS не защищён` | rescue не нужен |
| `EMERGENCY` / `probing` | causal candidate probes без влияния на клиентов | `Проверяем аварийный DNS` | применить только доказанный путь |
| `EMERGENCY` / `active_proxy` | rescue chain -> DoH через proxy | `Аварийный DNS через туннель` | продолжать normal-path probes |
| `EMERGENCY` / `active_direct` | rescue chain -> direct DoH | `Аварийный DNS напрямую` | degraded; продолжать normal-path probes |
| `EMERGENCY` / `active_*`, текущий кандидат умер | изолированно проверить следующий operator, затем transport | `Переключаем аварийный DNS` | swap + post-check либо snapshot + `failed` |
| `EMERGENCY` / `failed` | клиентские правила не изменены | `Аварийный DNS не помог` | сохранить direct route, без цикла |
| `EMERGENCY` / `recovering` | coordinated DNS + data-plane cutover | `Возвращаем обычный режим` | commit только после post-check |

### 5.4. Автоматический вход, ручные сессии и выход

Автоматический probe допускается только при `automat_state=EMERGENCY`, после завершённой
штатной лестницы и при `emergency_manual != 1`. Ручной sticky `EMERGENCY` автоматика не
изменяет; владелец может отдельно запустить manual DNS rescue, который не снимает ручной
режим и не разрешает последующий автоматический выход.

Apply разрешён только при causal proof из одного synthetic WG client path:

1. обычный DNS и контрольное приложение через текущий клиентский путь не работают;
2. IP/TLS-связность до тех же контрольных целей работает без зависимости от этого DNS;
3. выбранный DoH-кандидат разрешает имя с валидной TLS identity;
4. приложение открывается с полученным адресом и правильным SNI через тот же будущий
   client/data-plane path.

Server-side DoH success сам по себе недостаточен. Общая IP-недоступность, broken WG path или
неуспешный application/SNI check дают `failed/UNAVAILABLE` без apply. Это также не позволяет
ошибочно лечить `FROZEN_NET` сменой DNS.

`recovery_attempt_id` создаётся один раз при автоматическом входе в `EMERGENCY`, хранится
через reboot и закрывается только подтверждённым `NORMAL` либо явным ручным reset. P0 допускает
не более одной automatic probe-series и одной activation на incident. Счётчики durable;
reboot/watchdog tick их не обнуляет. Дополнительная попытка — только отдельная ручная команда;
автоматический retry после cooldown в P0 запрещён.

Каждая операция получает durable `dns_rescue_operation_id` и ровно один scope:

- `isolated_manual`: только operation id, exact test peer, `profile_class`, snapshot и
  `expires_at`; глобальный phase остаётся `idle`, exit удаляет только scoped rules;
- `node_wide_manual`: operation id + `manual_emergency_ref`; допустим только при
  `automat_state=EMERGENCY` и `emergency_manual=1`, а exit возвращает rescue phase в `idle`,
  сохраняя emergency flag и sticky manual state;
- `node_wide_automatic`: operation id + durable `recovery_attempt_id`; только этот scope
  может выполнить coordinated exit из `EMERGENCY` в `NORMAL`.

`manual_emergency_ref` создаётся при ручном включении `EMERGENCY` и не подменяется rescue.
Завершить или снять manual `EMERGENCY` может только владелец.

Если уже активный listener/resolver теряет здоровье, режим не оставляет redirect в blackhole.
После bounded consecutive failures он pre-probes следующий кандидат на изолированном path:
сначала другого resolver operator на том же transport, затем следующий transport. Успешный
кандидат получает controlled backend swap + post-check. Если кандидатов нет, coordinator
снимает rescue redirect, восстанавливает emergency DNS snapshot, проверяет UDP/TCP из
synthetic WG path и только затем ставит `phase=failed`; если исходный DNS по-прежнему не
работает, UI показывает `UNAVAILABLE`. Proxy rotation/purchase и новый recovery-loop запрещены.

Для `node_wide_automatic` обычный `_leave_direct` не может завершиться при
`dns_rescue_phase != idle`; выходом владеет coordinator. `node_wide_manual` и
`isolated_manual` вообще не вызывают автоматический выход из `EMERGENCY`: они восстанавливают
только свой DNS scope. Minimum dwell защищает от flapping, но не выключает работающий rescue
по таймеру.

### 5.5. Firewall и единый владелец состояния

- Отдельные собственные chains для DNS; не `flush` встроенного `PREROUTING`/`OUTPUT`.
- Один writer и общий lock для installer, updater, panel, watchdog и rollback.
- `global_rescue_chain` направляет WG-клиентский UDP/TCP 53 к listener только при
  `dns_rescue_phase=active_*`; вне режима глобальная chain не меняет трафик.
- Отдельная `scoped_test_chain` разрешена при `NORMAL/idle` только вместе с активным manual
  `dns_rescue_operation_id`, точным match test peer/source, заявленным `profile_class`,
  snapshot и обязательным `expires_at`. Она не может захватить других клиентов; expired
  session удаляется fail-safe janitor/reconcile.
- Listener слушает только WG-IP и loopback, recursion разрешена только WireGuard-подсети,
  WAN-доступ к нему запрещён.
- В активном режиме server-side процессы используют loopback. Local direct DNS разрешён
  только выделенной identity и к точным IP разрешённых resolver; secure rescue traffic не
  имеет прямого WAN egress на 53/853. Canary получает временное точечное исключение.
- `INPUT`, client `PREROUTING/FORWARD` и server `OUTPUT` проверяются отдельно для IPv4/IPv6.
- P0 enforcement/leak-free gate относится только к IPv4. При `ipv6_capture=off` IPv6
  counters собираются наблюдательно и дают `unmanaged/unknown`, а не PASS/green.
- До rollout фиксируется backend (`iptables-legacy` или nft), атомарная замена правил и
  counters; смешанный backend без доказательства effective rules запрещён.

### 5.6. Application DNS — честная граница

Redut может контролировать обычный UDP/TCP 53 и известные DoT/DoQ-порты. Произвольный
application DoH/DoH3 поверх 443 без TLS interception надёжно перехватить нельзя. В full
tunnel он остаётся за proxy egress, но обходит split/cache; в `EMERGENCY` может стать direct.
Панель поэтому показывает `application DNS: unmanaged`, а не ложную полную защиту. Массовая
блокировка известных DoH endpoint и TLS interception не входят в P0.

### 5.7. DNS transition saga

Каждый переход — идемпотентная saga `dns_rescue_transition` с обязательными
`dns_rescue_operation_id` и `scope`. Только `node_wide_automatic` требует
`recovery_attempt_id`; `node_wide_manual` требует `manual_emergency_ref`, а
`isolated_manual` — peer/profile/expiry. Saga хранит desired generation, checksum до/после,
фазу, причину и effective observations.
«Атомарность» здесь
не означает единую транзакцию systemd + firewall + routes; безопасность обеспечивает порядок:

1. взять общий lock и проверить scope-specific preconditions: automatic incident,
   sticky manual emergency либо isolated peer/profile/expiry;
2. снять snapshot listener/backend, dedicated chain, routes, cache generation и counters;
3. подготовить новый listener/backend без направления клиентского трафика;
4. выполнить loopback/TLS/bootstrap probe;
5. через временный test-only mark/chain либо отдельный test peer выполнить полный synthetic
   WG DNS + application/SNI probe по будущему client/data-plane path, не затрагивая остальных;
6. снова проверить preconditions — восстановившийся normal path отменяет устаревший apply;
7. последним коротким шагом заменить только scoped test chain либо, для node-wide операции,
   атомарно заменить **только dedicated rescue chain**;
8. выполнить synthetic WG post-check: для `isolated_manual` только заявленного
   `profile_class`, для node-wide scope — всех классов, присутствующих на узле;
9. после успеха isolated operation получает `session_active`, не меняя global phase;
   node-wide операция записывает `active_proxy|active_direct`. При ошибке isolated scope
   восстанавливает свой snapshot, а node-wide — emergency snapshot и проверяет его path.

Exit зависит от scope:

- `isolated_manual`: удалить scoped chain, проверить исходный peer path, закрыть operation;
- `node_wide_manual`: восстановить emergency DNS snapshot, поставить phase=`idle`, но сохранить
  emergency flag, `automat_state=EMERGENCY` и `emergency_manual=1`;
- `node_wide_automatic`: подготовить/shadow-проверить normal DNS, под тем же lock согласованно
  переключить DNS и middleman route, выполнить post-check и лишь затем очистить emergency
  flag/phase и зафиксировать `NORMAL`.

При неуспешном node-wide exit coordinator возвращает `EMERGENCY + rescue`, а не оставляет
смешанное состояние.

После kill/reboot решение принимается по journal phase и фактическим listener, firewall
counters, route, cache generation и end-to-end запросу: prepared-only очищается; redirect без
commit либо подтверждается post-check, либо откатывается. Автоматически реконструируется
только прежняя node-wide сессия того же incident/manual reference, не более трёх bounded
раундов. `isolated_manual` после reboot всегда очищается и требует новой ручной сессии:
monotonic TTL нельзя безопасно переносить между boot. Установщик, который заменяет
`dns/inbounds/log` из шаблона, обязан иметь ownership/migration-схему, иначе reinstall может
отменить новую policy.

### 5.8. Hardening listener

Минимальные привилегии; per-client QPS/burst, global outstanding, TCP connection/idle limits,
bounded cache/queue/RR-count/response-size; при перегрузке — bounded `SERVFAIL`. Query logging
по умолчанию выключен. Для EDNS0 стартовая гипотеза — 1232 bytes, но значение утверждается
только после измерения WireGuard overhead; обязательны TC + TCP retry, DNSSEC-large-response
и dropped-fragment тесты.

## 6. Независимая диагностика DNS

### 6.1. Матрица контрольных запросов

Использовать только контролируемые запросы:

1. benign canary — существующая стабильная запись из нескольких trust-domain;
2. owned canary — одноразовый случайный label собственной зоны против cache hit;
3. service canary — заранее заданный проверяемый сервис, уже используемый health-контуром;
4. прямой UDP/53;
5. прямой TCP/53;
6. удалённый DoH через боевой proxy;
7. IPv4 и IPv6 — раздельно, когда IPv6 включён.

Фиксировать:

- transport и view;
- RCODE;
- наличие ответа, SOA и CNAME;
- A/AAAA present, но не требовать точного совпадения IP у CDN;
- TLS identity, CA/time status и DNSSEC status; `AD` без локального validating resolver не
  считается самостоятельным доказательством подлинности данных;
- latency и timeout;
- источник маршрута: direct/tunnel/emergency;
- время и случайный opaque `canary_id` с bounded retention.

Не фиксировать полный pcap пользовательского трафика и произвольные QNAME. Живая проверка
пакетов выполняется BPF-фильтром только по canary endpoint/порту и в ограниченном окне.
Canary labels не содержат стабильный node-id, запускаются с jitter и не позволяют внешнему
наблюдателю однозначно атрибутировать запрос оператору. Собственная зона и registrar входят
в мониторинг как отдельная зависимость.

### 6.2. Классификация

Добавить отдельное чистое решение `dns_health_decision`, не расширяя
`proxy_fault_decision` DNS-сигналами.

Это DNS-evidence внутри `dns_rescue_phase=probing|active_*`, а не новые значения
`automat_state`:

- `PROTECTED` — аутентифицированный rescue transport подтверждён, direct leak не обнаружен;
  это не обещание локальной DNSSEC-валидации;
- `SPLIT_OK` — secure rescue path + local RU-view и route-claim consistency доказаны. Пока
  provenance/shared-IP/TTL контракт не принят, допустимо только честное состояние
  `secure DNS + legacy RU split`;
- `INTERFERENCE_SUSPECTED` — direct и remote семантически расходятся по независимым canary;
- `RESOLVER_DEGRADED` — один secure endpoint отказал, резерв работает;
- `RESCUE_DIRECT` — работает только аутентифицированный DoH напрямую через WAN;
- `UNAVAILABLE` — DNS не работает ни одним разрешённым путём;
- `UNKNOWN` — недостаточно свежих данных.

Отдельно классифицируются: TLS hostname/certificate, системное время, CA/trust store,
bootstrap, `NXDOMAIN`, `NODATA`, `SERVFAIL`, `REFUSED`, DNSSEC `BOGUS`, truncation/TCP retry,
resource exhaustion и listener/firewall mismatch. Эти причины не сворачиваются в `timeout`.

Для `INTERFERENCE_SUSPECTED` нужны минимум два независимых доказательства в ограниченном
окне либо повторяемое расхождение direct/remote для owned canary. Один NXDOMAIN или один
timeout остаётся `UNKNOWN/DEGRADED`, но не «перехватом».

## 7. Кэш и согласованность маршрутизации

1. Разделить secure/local/degraded cache и поколения policy логически или физически.
2. Каждый direct route — claim с `view`, allowlisted suffix, полной alias chain, qtype,
   RRset hash, generation, `expires_at` и refcount; голый IP из ответа не является policy.
3. В `RESCUE_DIRECT` не создаются route claims. Отрицательный ответ живёт минимальное
   техническое время; synthetic-looking NXDOMAIN предпочтительно не кэшировать.
4. При выходе из `RESCUE_DIRECT/dns_rescue_phase=active_*` удалить rescue generation и
   negative cache. Сервер не может удалённо очистить browser/OS cache клиента, поэтому UI
   остаётся `recovery pending` до истечения выданного TTL.
5. Route устанавливается атомарно **до** отдачи ответа. Existing flow закрепляется через
   conntrack/connmark; истечение TTL меняет только новые соединения.
6. Timeout claim не больше минимального оставшегося RR TTL и защитного maximum. `TTL=0` не
   создаёт persistent claim; искусственный minimum, продлевающий разрешение, запрещён.
7. Финальные A/AAAA принимаются только после проверки всей CNAME-chain. Cross-view alias
   по умолчанию не получает direct; depth, RR count, response size и число адресов bounded.
8. `HTTPS/SVCB ipv4hint/ipv6hint` не являются route authority без отдельной валидации.
9. NXDOMAIN, NODATA, SERVFAIL, REFUSED, DNSSEC BOGUS и truncated response имеют разную
   cache/health-семантику.
10. IPv4 и IPv6 используют разные sets/claims и одинаковую policy validation.
11. Shared-IP CDN означает, что глобальный ipset не даёт hostname isolation. ADR должен
    выбрать domain-aware routing либо явно принять и ограничить legacy split; до этого
    заявлять строгий `SPLIT_OK` нельзя.

## 8. IPv6 leak guard

Текущий IPv4-only клиентский профиль не должен молча считаться full tunnel.

### Этап A — безопасное явное поведение

- `ipv6_capture=off` означает `IPv4 rescue covered / IPv6 unmanaged`, поэтому общий green
  запрещён и вне активного rescue защита IPv4 также не обещается.
- Сервер не может достоверно определить remote native IPv6 клиента: нужен client-side canary,
  а до него — предупреждение и явный unknown/unmanaged статус.
- Инвентаризировать старые профили: часть клиентов использует `1.1.1.1`, часть WG-IP; для
  новых DNS/IPv6 гарантий может потребоваться повторный импорт профиля.
- Подавление AAAA не является leak protection, поскольку приложение может использовать DoH.
- Подготовить режим `ipv6_capture = off | block | tunnel`, default `off` до приёмки.

### Этап B — canary

- Либо полноценный IPv6 через WireGuard/tun/proxy;
- либо `::/0` с контролируемым reject/blackhole как fail-closed для IPv6.

Canary обязан проверить IPv6-only сеть, Happy Eyeballs, AAAA, QUIC/UDP и доступность
WireGuard endpoint, отдельно outer WireGuard IPv6 и inner client IPv6, а также PMTUD/ICMPv6
и NAT64. Нельзя массово добавлять `::/0`, пока отдельная cohort-приёмка не доказала, что это
не лишает клиентов связи в мобильных сетях.

Решение и честный UI входят в P0; полноценный IPv6 rollout — отдельный P1/cohort и не
объединяется с первым `DNS_RESCUE` canary.

## 9. Конфигурация и безопасные defaults

Предварительная схема; точные имена утверждаются при реализации:

```json
{
  "dns_rescue": {
    "mode": "observe_only",
    "activation_point": "after_recovery_exhausted",
    "transport_order": ["doh_via_proxy", "doh_direct_wan"],
    "resolver_candidates": [],
    "candidate_selection_policy": "resolver_failover_before_transport_downgrade",
    "apply_policy": "probe_then_saga_activate",
    "failure_policy": "keep_emergency_and_report_unavailable",
    "automatic_retry_policy": "none_until_incident_closed",
    "automatic_max_probe_series_per_incident": 1,
    "automatic_max_activations_per_incident": 1,
    "operation_scopes": ["isolated_manual", "node_wide_manual", "node_wide_automatic"],
    "split_mode": "legacy_ru_observe",
    "firewall_mode": "inactive",
    "observe_probe_interval_seconds": 1800,
    "incident_first_probe": "immediate",
    "ipv6_capture": "off"
  }
}
```

Правила нормализации:

- допустимая лестница `disabled -> observe_only -> manual_canary -> automatic_last_resort`;
- неизвестный режим -> `disabled`, существующий DNS остаётся без изменений;
- каждый resolver candidate задаётся записью `{operator, endpoint, transport, sni,
  address_generation, not_after}`; candidate — это resolver × transport, а не только URL;
- пустой список `resolver_candidates` запрещает `manual_canary/automatic_last_resort`;
- readiness истекает по самому раннему `not_after` TLS/bootstrap proof; address rotation имеет
  overlap и LKG, просроченный candidate не считается готовым;
- комбинации задаются allowed-state matrix, а не независимыми booleans: например,
  active `global_rescue_chain` вне `EMERGENCY + dns_rescue_phase=active_*` запрещена;
  `scoped_test_chain` при `NORMAL/idle` допустима только для active `isolated_manual`
  operation с exact peer/profile match, snapshot и непросроченным `expires_at`;
- `SPLIT_OK` без route-claim engine запрещён;
- `automatic_last_resort` невозможен без пройденного manual canary для всех классов профилей,
  rollback drill, списка узлов и owner approval;
- опасные значения не наследуются как enabled из битой строки; invalid combination не
  получает green и блокирует apply;
- конфиг мигрируется с backup и dry-run;
- старые узлы после обновления продолжают работать по прежней схеме;
- owner approval и список canary-узлов — отдельные гейты, как у learning v2.

## 10. Данные, метрики и UI

### 10.1. Хранение

Разделить operational authority и историю evidence.

Bounded-таблица `dns_probe_log`, не смешанная с proxy `probe_log`, хранит только историю:

- `ts`, `server`, `view`, `transport`, `canary_id`;
- `ok`, `rcode`, `answer_present`, `soa_present`, `dnssec_status`;
- `latency_ms`, `route_path`, `error_kind`;
- resolver identity/operator, evidence age и IPv4/IPv6 coverage;
- без QNAME, IP клиента, URL с секретами и raw exception.

Отдельный durable `dns_rescue_state` на узел хранит current phase, active operation,
`recovery_attempt_id`, manual-emergency reference, probe/activation counters, desired/effective
и cache generations. Отдельный `dns_rescue_operations` — scope, peer/profile/expiry,
journal phase, snapshots, checksums и terminal result.

Active incident, current state и незавершённые operations **не** удаляются обычной retention.
Terminal operation архивируется только после reconcile с effective listener/firewall/route;
очистка `dns_probe_log` никогда не обнуляет incident counters и не разрешает новую automatic
series. Запись evidence и продвижение journal связываются транзакцией либо существующим
transaction helper.

### 10.2. Панель

Добавить одну компактную карточку:

- `Аварийный DNS готов, не используется`;
- `Проверяем аварийный DNS`;
- `Работаем через аварийный DNS по туннелю`;
- `Работаем через аварийный DNS напрямую`;
- `Аварийный DNS не помог`;
- `Возвращаем штатный режим`;
- `Недостаточно данных`.

Раскрываемая диагностика показывает `automat_state`, ортогональный `dns_rescue_phase`,
`recovery_attempt_id`, transport, resolver slot, latency, RCODE, свежесть, причину перехода,
desired/effective state,
resolver operator, cache generation, IPv4/IPv6
coverage, `application DNS: managed/unmanaged` и факт очистки server cache. Пользовательские
домены не показываются. `PROTECTED` подписывается как защита транспорта, а не как DNSSEC.

### 10.3. Метрики

- synthetic availability из отдельного WG client/network namespace;
- доля времени защищённого транспорта внутри rescue и отдельно доказанного `SPLIT_OK`;
- число входов в `dns_rescue_phase=probing`, доля успешной активации и причины отказа;
- время `dns_rescue_phase=active_*`/`RESCUE_DIRECT`, разделённое на вход, работу и recovery;
- число инцидентов, где штатный `EMERGENCY` восстановил доступ и rescue не запускался;
- число resolver failover;
- direct/remote semantic mismatch;
- DNS MTTR;
- cache flush success/failure;
- IPv6 leak check;
- WAN violation counters для OUTPUT/FORWARD 53/853: IPv4 как P0 gate, IPv6 как observe-only
  до отдельного `block|tunnel` canary;
- route-claim/cache-generation consistency;
- p50/p95 latency и age последнего end-to-end evidence;
- DNS-only события, которые **не** вызвали proxy rotation;
- data-quality: stale, malformed, truncated, future rows.

DNS-метрики не входят в proxy score и learning на первом релизе. Возможный выбор лучшего
resolver по истории проходит отдельные shadow/canary gates не раньше накопления достаточных
данных.

До manual canary ADR обязан задать численные пороги: maximum activation latency, minimum DNS
availability, maximum p95 latency regression и recovery time. Для automatic canary жёсткие
гейты: `false automatic activations = 0` и `successful rollback drills = 100%`. Пустые пороги
или «визуально нормально» не разрешают переход к следующему этапу.

## 11. Пакеты реализации

### Пакет -1 — security preflight, до любой публикации

- С владельцем проверить, являются ли непустые upstream-поля в canonical/public шаблонах
  только тестовыми placeholder. Значения не выводить в отчёт и не проверять во внешней сети.
- Если это рабочие credentials: остановить публикацию, отозвать/сменить их и очистить
  canonical/public/history по отдельному incident-плану с явным одобрением владельца.
- Запретить секреты в шаблонах и добавить secret scanning как release gate.

**Стоп-гейт:** DNS canary не начинается, пока владелец не закрыл credential exposure как
отдельный инцидент. Этот пакет не даёт разрешения на rotation или rewrite history.

### Пакет 0 — threat model, read-only baseline и ADR

- Проверить живую схему DNS на каждом узле без изменений: старые client profiles, listener,
  маршруты, effective firewall backend/counters, direct/tun, `EMERGENCY`, IPv4/IPv6.
- Построить dependency DAG: proxy endpoint, DoH endpoints/operator, bootstrap, CA/time,
  installer/update и owned-canary zone.
- Доказать UDP/TCP 53 end-to-end через отдельный synthetic WG client namespace.
- Сравнить sing-box gateway и dnsmasq + loopback stub; проверить совместимость с `1.11.7`.
- Зафиксировать ownership installer/reinstall и оформить ADR.
- В ADR зафиксировать численные SLO/gates для latency, availability, false activation,
  recovery и rollback до любого canary.
- Для узла с действующим external RU updater: до P0 canary заморозить его на проверенном LKG
  либо исключить узел. Недоверенный tip не может продолжать менять direct set; полный
  hardened split остаётся отдельным P1.

**Стоп-гейт:** никаких live-правил или resolver replacement до письменного утверждения ADR;
узел с незакрытым allowlist supply-chain риском не допускается в canary.

### Пакет 1 — observe-only и правдивый UI

- Версионированный allowed-state config с fail-safe defaults.
- Чистые evidence/decision, `dns_probe_log`, bounded retention и строгая сериализация.
- Read-only диагностика с аутентификацией resolver, error taxonomy, SLO и counters.
- Панель показывает desired/effective, coverage и `UNKNOWN/наблюдение`, но не переключает.

**Критерий:** обновление старого узла не меняет ни маршруты, ни DNS-пакеты, ни профили.

### Пакет 2 — безопасный фундамент `DNS_RESCUE` и ручной canary

- Минимум два DoH resolver operators; для каждого явно перечислены проверенные transports.
  Сначала failover между operators через proxy, и лишь затем degraded downgrade всех
  кандидатов на direct WAN; каждый вариант имеет валидную TLS identity.
- Bootstrap без перехватываемого DNS; проверенный источник/хэш бинарника sing-box.
- Выбранный listener принимает UDP/TCP 53 на WG-IP, закрыт с WAN и подтверждён synthetic
  WG client; точечный ingress/interception включается только внутри ручной canary-сессии.
- До первого включения готовы inactive dedicated chains, общий lock, ownership, transition
  journal, snapshot/rollback, crash/reboot reconciliation и effective-state post-check.
- Реализованы scope-specific contracts: expiring isolated test chain, sticky node-wide manual
  exit и automatic operation, связанная с durable incident id; operational state не хранится
  в очищаемом probe log.
- Старые профили `DNS=1.1.1.1` и профили с WG-IP инвентаризированы; manual canary проверяет
  UDP/TCP для каждого класса, реально присутствующего на выбранном узле.
- Resolver failover без покупки/смены proxy и без расширения legacy RU split.
- Вне manual canary штатный DNS и firewall остаются неизменными.

**Критерий:** manual `DNS_RESCUE` проходит end-to-end и полностью снимается без изменения
штатного DNS; kill/reboot и частичный apply возвращают snapshot; UI показывает охват всех
профилей и transport.

### Пакет 3 — автоматический last-resort trigger

- `automat_state` остаётся `EMERGENCY`; меняется только ортогональный `dns_rescue_phase`.
- Trigger возможен после исчерпания recovery в том же durable `recovery_attempt_id`, но
  автоматически запрещён при `emergency_manual=1`.
- Causal proof проверяет DNS failure + рабочую IP/TLS-связность + candidate answer +
  application/SNI success; общая IP-недоступность не допускает apply.
- `probe_then_saga_activate`: неуспешный candidate и устаревшие preconditions не меняют DNS.
- Automatic gate требует UDP/TCP post-check всех классов профилей на узле; непокрытый класс
  блокирует режим для всего узла до миграции.
- Одна automatic probe-series/activation на incident, без proxy rotation/purchase и loop.
- `_leave_direct` передаёт выход coordinator, пока `dns_rescue_phase != idle`.

**Критерий:** trigger не нарушает manual `EMERGENCY`, не лечит total network failure сменой
DNS, восстанавливает доступ только в causal DNS-сценарии и согласованно возвращает
`dns_rescue_phase=idle` перед завершением `EMERGENCY`.

### Пакет 4 — P1: optional hardened split-routing внутри rescue

- Карантин RU allowlist: pinned source/revision/checksum, schema parser, reviewed diff,
  deny special/default/control ranges, size/churn bounds, LKG и owner approval.
- Updater меняет только поколение allowlist; не запускает весь boot script и не трогает
  built-in chains/routes. Atomic apply под общим lock.
- Route claims с provenance/refcount/TTL, full CNAME validation, HTTPS/SVCB policy,
  IPv4/IPv6 sets, shared-IP решение и connmark для существующих flows.
- Раздельные cache generation и negative cache.

**Критерий:** только доказанные RU-claims получают direct; malicious list/response не может
добавить `0.0.0.0/0`, `::/0` или control address; ложный NXDOMAIN не загрязняет secure view.

### Пакет 5 — отдельный IPv6 cohort

- До canary: честный `IPv4 rescue covered / IPv6 unmanaged`, client-side check и inventory.
- Затем отдельно принять `block` или полноценный `tunnel`.
- Проверить outer/inner IPv6, IPv6-only, dual-stack, NAT64, Happy Eyeballs, PMTUD/ICMPv6.

**Критерий:** нет скрытого IPv6 обхода и потери связи у утверждённой cohort.

### Пакет 6 — локальная DNSSEC-валидация

- Отдельный ADR по trust anchors, clock failure, `BOGUS` и обновлению ключей.
- Не использовать upstream `AD` как замену локальной валидации.

Этот пакет P1 и не блокирует транспортную защиту, но до него UI не обещает DNSSEC.

### Пакет 7 — fleet radar, только после локальной зрелости

- После privacy review агрегировать обезличенные canary-результаты по серверу/ASN/региону.
- Не передавать QNAME пользователей, стабильный node-id и секреты узла.
- Не делать автоматических proxy-покупок; сначала только отчёт/shadow-рекомендация.

Этот пакет P2 и не должен задерживать локальную защиту DNS.

## 12. Предполагаемые файлы реализации

Точный diff определяется после ADR, но ожидаются изменения в:

- `install/templates/sing-box.config.json`;
- `install/install.sh`, `install/templates/update-ru-whitelist.sh`, boot/firewall templates
  и `install/templates/dnsmasq/`;
- `panel/config_schema.py`;
- `panel/health.py` — отдельное DNS-решение, без расширения proxy quorum;
- `panel/states.py` — только интеграция с `EMERGENCY` и recovery;
- `panel/pool.py` — schema/migration/retention;
- `panel/metrics.py`;
- `panel/webpanel/server.py` и `panel/webpanel/views.py`;
- `panel/webpanel/clients.py` — IPv6 только на соответствующем этапе;
- `panel/tests/` и `CHAOS-MATRIX.md`;
- CI/release secret scan, binary provenance/checksum и public-build verifier;
- `README.md`, `install/README.md`, `panel/README.md`, node runbooks и release notes.

Ручное редактирование `Гитхаб/` запрещено. После приёмки публичная копия пересобирается,
проверяется на секреты и прогоняет тот же набор тестов.

## 13. Обязательная тестовая матрица

### Unit/contract

- повреждённый/старый конфиг;
- свежесть и quorum DNS evidence;
- NXDOMAIN/SERVFAIL/REFUSED/timeout;
- NODATA/DNSSEC BOGUS/TLS identity/expired certificate/bad clock/truncated + TCP retry;
- direct/remote mismatch;
- DNS-only anomaly не меняет proxy, MANUAL и деньги;
- `DNS_RESCUE` не входит до исчерпания recovery для того же `recovery_attempt_id`;
- `emergency_manual=1` блокирует automatic rescue и automatic exit;
- manual canary из `NORMAL` разрешён только scoped test peer; node-wide manual rescue требует
  sticky manual `EMERGENCY` и не снимает его при завершении;
- каждая операция получает `dns_rescue_operation_id`, automatic связывается с incident id;
- expired/missing-peer scoped session удаляется без изменения global phase;
- retention `dns_probe_log` не удаляет current state, open journal и incident counters;
- durable incident id/counters не сбрасываются watchdog tick и reboot;
- total IP/WG failure и server-only DoH success не проходят causal gate;
- normal path, восстановившийся перед redirect, отменяет stale apply;
- failed candidate probe не меняет listener/firewall/client DNS;
- одна bounded automatic probe-series на incident; попытка резервируется до первого внешнего
  client/server probe, поэтому повторный watchdog call не запускает новые probes;
- reboot/exit compensation ограничена тремя durable раундами, связана с тем же incident ID
  либо manual reference; terminal exhaustion удаляет replay-дескриптор и требует явного
  действия владельца;
- истечение isolated TTL обрабатывается до boot/WG/service inspection и никогда не
  продлевается состоянием `unknown`;
- candidate `not_after` ограничивает deadline observe/activate/failover и проверяется перед
  каждым новым сетевым действием и commit;
- WireGuard client CRUD запрещён при active/open/resume DNS ownership, имеет durable
  forward/rollback journal и принимает для delete только один exact IPv4 `/32`;
- resolver failover не меняет текущий upstream;
- cache transition идемпотентен;
- bounded retention и strict JSON;
- секреты/QNAME не попадают в события и API.
- invalid state combination fail-closed;
- allowlist parser отвергает `0.0.0.0/0`, `::/0`, private/control ranges, excessive churn,
  unpinned revision и непроверенный формат;
- route claim: cross-view CNAME, loop, depth/size limit, TTL=0, refcount и shared IP.

### Integration

- dnsmasq config test;
- sing-box config check;
- controlled query через каждый view;
- в `NORMAL/RECOVERY` rescue chain не меняет ни одного пакета;
- manual canary проходит saga phases и откат каждого промежуточного шага;
- isolated scope post-check проверяет только заявленный profile class; node-wide — все
  присутствующие классы;
- pre-apply synthetic test-only path доказывает будущий DNS + application/SNI до global redirect;
- UDP/TCP-проверки отдельно для реально присутствующих WG-IP и `DNS=1.1.1.1` профилей;
- `_leave_direct` не завершает `EMERGENCY`, пока `dns_rescue_phase != idle`;
- node-wide manual rescue exit сохраняет emergency flag и `emergency_manual=1`;
- UDP и TCP 53 от WG-клиента до фактического listener; WAN recursion/port 53 закрыты;
- A/AAAA/CNAME/HTTPS/SVCB;
- короткий и длинный TTL;
- browser/app DoH;
- QUIC/UDP;
- install и reinstall с сохранением client/config/state;
- crash на каждом шаге WireGuard add/delete сохраняет согласованность live peer, `wg0.conf`
  и client `.conf`; секретный temp всегда `0600`, fsync/replace и root-owned;
- reboot в штатном режиме и при node-wide `EMERGENCY + dns_rescue_phase=active_proxy|active_direct`;
- reboot при `active_isolated` очищает scoped session без автоматического восстановления;
- rollback к старому DNS-пути.
- install/reinstall не меняют DNS ownership и не возвращают credentials в public template;
- В P0 IPv4 OUTPUT/FORWARD counters и synthetic WG namespace подтверждают effective egress;
  IPv6 только измеряется как `unmanaged/unknown` и не участвует в leak-free gate.

### Chaos

- один DoH endpoint недоступен;
- все DoH endpoint недоступны, proxy жив;
- direct resolver перехвачен/возвращает NXDOMAIN;
- local resolver timeout;
- proxy умер при живом direct WAN;
- штатный recovery и `EMERGENCY` не помогли, но direct DoH восстановил DNS;
- все rescue-кандидаты неуспешны: правила не применены, цикл не перезапущен;
- исходный путь восстановился при `dns_rescue_phase=active_*`;
- текущий resolver умер после activation: другой operator того же transport проходит первым;
- listener и все resolver candidates умерли после activation: redirect снят, emergency snapshot
  восстановлен, phase=`failed`, повторная recovery/purchase не запущена;
- crash после prepare, после redirect и до commit с восстановлением snapshot;
- mixed-profile узел, где один класс не прошёл post-check, блокирует automatic activation;
- kill/reboot во время смены DNS-режима;
- crash между фазами listener/firewall/cache generation и повторный идемпотентный reconcile;
- disk full/SQLite busy/corrupt;
- CA bundle/clock/bootstrap failure и TLS redirect/downgrade;
- compromised/malformed RU allowlist, broad CIDR и rollback на LKG;
- IPv4 жив, IPv6 уходит мимо;
- stale negative cache после восстановления;
- быстрые повторные переходы secure/direct/secure.

Chaos на боевом узле выполняется только по одному сценарию, под наблюдением владельца,
с заранее проверенным SSH/панельным доступом и готовым rollback. Серии рестартов sing-box
не допускаются.

## 14. Порядок публикации и production rollout

1. Закрыть пакет -1: owner-verified secret preflight; при подтверждении утечки — отдельный
   incident plan до продолжения.
2. Утвердить threat model, live inventory, dependency DAG и ADR.
3. Локальные unit/contract/security-тесты и изолированная install/reinstall-приёмка.
4. Публичная сборка P0, clean-install, secret/provenance scan, release notes и публикация
   исходного кода без включения режима в production.
5. Observe-only на одном явно утверждённом canary-узле с точечным firewall exception.
6. Не менее нескольких полных циклов наблюдения без изменения трафика; длительность
   определяется baseline, а не календарным предположением.
7. Изолированный manual canary из `NORMAL` только на test peer/namespace для каждого
   присутствующего класса профилей; затем отдельный node-wide manual test из sticky
   `EMERGENCY`. Сначала DoH через proxy, затем отдельный сценарий direct DoH.
8. Rollback/kill/reboot drill и доказательство, что вне сессии штатный DNS не меняется.
9. Shadow-trigger `after_recovery_exhausted`: решение журналируется, но режим не включается.
10. Автоматический last-resort только на одном owner-approved узле, где UDP/TCP прошли для
   всех присутствующих классов профилей; `LOCAL_RU=observe_only`.
11. Сравнение baseline/rescue/failure/recovery SLO, counters и отдельный owner approval.
12. Второй узел.
13. Отдельным P1: hardened allowlist/route-claim engine и local-RU внутри rescue.
14. Отдельным P1: IPv6 cohort после стабилизации IPv4.

Каждый пункт — отдельный откатный рубеж. Нельзя объединять первое ручное включение rescue,
automatic trigger, allowlist engine и IPv6 в один деплой.

## 15. Rollback

Если candidate probe не дошёл до apply, rollback является no-op и только фиксирует failure.
После активации rollback должен быть подготовлен и отрепетирован: он не начинает с удаления
рабочей rescue-точки входа, иначе клиенты могут остаться без DNS:

1. поднять из versioned backup известный рабочий listener/upstream и проверить конфиг;
2. synthetic WG-клиентом доказать UDP/TCP query и доступность upstream;
3. под общим lock в заданном порядке восстановить firewall chains/routes;
4. повторить end-to-end query и проверить WAN counters;
5. только после этого отключить новую policy и очистить **только** её cache/state/generation;
6. проверить direct/tunnel egress, старые профили (`1.1.1.1` и WG-IP) и текущих клиентов;
7. оставить событие rollback с фазой, причиной и checksum, без секретов.

Если полный возврат невозможен, система остаётся на доказанно работающем пути в
`automat_state=EMERGENCY + dns_rescue_phase=active_*` либо в обычном `EMERGENCY` с
постоянным жёлтым/красным статусом, а не выключает DNS.

Неуспешный `DNS_RESCUE` не должен требовать смены proxy или покупки нового адреса.

## 16. Критерии готовности к production rollout и automatic DNS

Публикация исходного кода не означает эксплуатационную готовность. Production rollout и
включение automatic DNS не готовы, пока не доказано всё ниже:

- пакет -1 закрыт владельцем; публичная сборка и canonical templates не содержат credentials;
- узел canary не получает непроверенный RU-list tip: updater зафиксирован на LKG/pinned
  snapshot либо узел исключён;
- вне `DNS_RESCUE` штатный DNS/data-plane побайтно и по effective counters не изменены;
- режим не входит раньше завершения штатного recovery и `EMERGENCY` для того же incident;
- manual canary из `NORMAL` доказанно ограничен test peer; node-wide manual rescue не снимает
  sticky `emergency_manual`;
- scoped test chain имеет exact peer/profile match и `expires_at`; global chain остаётся inactive;
- current phase/open operations/incident counters переживают probe-log retention и reboot;
  node-wide continuation допускается только для того же incident/manual reference и максимум
  три раунда, isolated session после смены boot identity не восстанавливается;
- failed candidate probe не меняет клиентский DNS, firewall и route state;
- при `dns_rescue_phase=active_*` выбранный DoH аутентифицирован,
  TLS/clock/bootstrap fail-closed;
- rescue listener обслуживает UDP/TCP 53 только в активном режиме, закрыт с WAN; после reboot
  node-wide путь проходит новую bounded proof-saga, а isolated listener/redirect очищаются;
- в P0 `LOCAL_RU` остаётся `observe_only` и не создаёт direct route claims;
- перед отдельным P1-включением split RU allowlist pinned/reviewed/bounded, имеет LKG и не
  может добавить broad/control ranges, а claims доказывают provenance/TTL/CNAME/consistency;
- `EMERGENCY` сохраняется до, во время и после неуспешной rescue-попытки;
- отказ active resolver/listener вызывает bounded operator-first failover либо снятие redirect
  и возврат emergency snapshot без proxy rotation/recovery-loop;
- панель не показывает green при active rescue, direct/degraded DNS или unknown coverage;
- recovery сначала доказывает normal path, затем снимает rescue chain и удаляет server-side
  stale cache, честно показывая остаточный client TTL;
- DNS-only anomaly не ротирует proxy и не тратит деньги;
- утверждённые в ADR численные activation/availability/p95/recovery thresholds выполнены;
  automatic canary имеет 0 false activations и 100% успешных rollback drills;
- plain 53/853 leak отсутствует внутри активного rescue по synthetic WG probes и effective
  OUTPUT/FORWARD counters; ожидаемый direct DoH/443 помечен как `RESCUE_DIRECT`;
  ограниченный packet capture — дополнительное, а не единственное доказательство;
- P0 production rollout явно ограничен IPv4: при `ipv6_capture=off` UI показывает
  `IPv6 unmanaged` и
  общий green запрещён; отсутствие IPv6 leak не является P0-критерием, а общий IPv4+IPv6
  rollout возможен только после `block|tunnel` canary;
- application DoH scope отображается как unmanaged там, где его нельзя контролировать;
- reboot/install/reinstall/rollback проходят;
- полный canonical и public test suites зелёные;
- публичная сборка не содержит credentials, private hosts и test artifacts;
- документация описывает фактическое поведение, а не намерение;
- владелец отдельно одобрил canary и production rollout.

## 17. Приоритет

### P0

1. Security preflight по возможным credentials; при подтверждении — отдельный incident plan.
2. Threat model, live inventory, dependency DAG, ADR и binary provenance.
3. Containment текущего external RU updater: проверенный LKG либо исключение узла из canary.
4. Observe-only evidence, effective-state counters, численные SLO и правдивый UI.
5. Inactive chains, journal/lock/reconcile, два DoH-кандидата и manual mixed-profile canary.
6. Trigger строго после recovery/`EMERGENCY`, causal proof и одна попытка на durable incident.
7. Coordinated exit с блокировкой обычного `_leave_direct` до `dns_rescue_phase=idle`.
8. IPv6/application-DNS границы и честный status; без массового `::/0`.

### P1

1. Отдельный full IPv6 cohort/tunnel.
2. Локальная DNSSEC-валидация и trust-anchor lifecycle.
3. Quarantine/pinning RU allowlist и hardened route-claim engine внутри rescue.
4. Domain-aware routing либо дальнейшее сужение legacy shared-IP split.
5. Resolver diversity/bootstrap rotation; privacy: ECS off, padding/QNAME minimization.
6. Per-peer quotas и расширенный DNS SLO/drift report.

### P2

1. Обезличенный fleet radar.
2. Shadow-выбор resolver transport по накопленной статистике.
3. Опциональный `integrity_first` после отдельного threat/UX review.
4. Эксперименты DoH3/DoQ/ODoH только после устойчивого базового контура.

Не начинать одновременно с этим проектом: learning resolver, полную рекурсию, блокировку
всех публичных DoH endpoint, TLS interception и upgrade sing-box. Это отдельные риски и ADR.

## 18. Итоговое решение плана

Не заменять штатный DNS Redut и не делать TCP/53 либо локальную полную рекурсию основным
ответом. Добавить ограниченный последний режим восстановления:

```text
NORMAL
  -> штатный RECOVERY/FAILOVER
  -> automat_state=EMERGENCY, dns_rescue_phase=idle
  -> если causal DNS failure доказан: dns_rescue_phase=probing
       -> успешный DoH-кандидат: phase=active_proxy|active_direct
       -> кандидатов нет: phase=failed без изменения клиентских правил
  -> после доказанного восстановления: NORMAL
```

`DNS_RESCUE` — не постоянная защита и не причина вмешиваться в работающую систему. Это
последняя контролируемая попытка РЕДУТА вернуть доступ, когда обычная лестница уже не помогла.
Режим сначала доказывает рабочий DNS-путь, затем включает его через rollback-safe saga,
остаётся явно
аварийным в UI и не ухудшает `EMERGENCY`, если сам не сработал.
