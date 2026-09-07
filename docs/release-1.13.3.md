# Редут 1.13.3 — исправление обновления и закрытие аудита

Дата: 2026-09-07

## Итог

Выпуск устраняет причину отката при обновлении 1.13.0 → 1.13.2 и закрывает
все подтверждённые дефекты отчёта по 1.13.2. Предложенный патч отчёта не
применялся вслепую: каждая находка воспроизведена, исправлена и проверена отдельно.

## Обновление с 1.13.0

В 1.13.0 читатель DNS Rescue возвращал виртуальное `idle`, если singleton-строка ещё не
была создана. Strict preflight нового установщика верно отказывался додумывать такое
состояние, но из-за этого точный legacy-узел не мог перейти на 1.13.2.

Теперь под общим lock разрешена одна узкая совместимость: точная схема 1.13.0,
нуль DNS-операций/дескрипторов/артефактов/правил/процессов, неактивный unit и `disabled`
без owner approval. Только при одновременном выполнении всех условий материализуется `idle`.
Любое другое или повреждённое состояние остаётся fail-closed.

## Подтверждённые исправления

- Web/auth: credential epoch связывает пароль, TOTP/recovery и сессию; recovery reload
  сериализован с БД. POST body имеет однозначный `Content-Length`, любой
  `Transfer-Encoding` отклоняется, а чтение имеет абсолютный deadline.
- Деньги: ProxyLine prolong заблокирован до provider mutation, пока нет доверенной
  preflight-цены, отдельного USD-бюджета и correlatable request id. Потеря ответа
  proxy6 сохраняет `submitted` для ручной сверки; более поздний `date_end` не выдумывает списание.
- Пул и update-state: сеть вынесена из SQLite writer transaction, выдача валидируется
  целиком, merge/vanished queue атомарны. `update.json` не теряет `bad_versions` и `last_apply`
  при одновременных check/apply.
- Apply/runtime: secret temp создаётся `0600`; старый anti-loop маршрут не удаляется
  до доказанной установки нового; IP заменяется по точной границе; restart/curl
  требуют нулевой rc.
- Транспорт и пробы: мутирующий POST не следует redirect и не повторяется после
  ambiguous reset/timeout; секреты не попадают в exception. `NO_PROXY` не обходит выбранный канал,
  IP парсится стандартной библиотекой, inconclusive-результат не портит здоровый score.
- Lifecycle: ошибка обязательной панели больше не возвращает ложный успех; deploy
  требует exact HTTPS `/healthz` и закрывает ресурсы. `--keep-config` проверяет live порт
  до upload; `--subnet` и `--clients` корректно работают с non-/24 и отклоняют тесные сети.
- DNS Rescue/Linux: INPUT-chain имена укладываются в 28-символьный лимит
  xtables. На `iptables-nft` отсутствующие owned jump-targets проверяются по
  списку родительской цепочки, а не через ложно-аварийный `iptables -C`.
- Policy routing: локальный `curl --interface tun0` больше не маскирует сломанный
  путь клиентов. Watchdog и агент требуют единственный `middleman default`, exact
  `fwmark 0x64` rule и фактический marked lookup через ожидаемый интерфейс. Чистый
  drift чинится под общим lock без рестарта; неуспешный локальный ремонт при живом
  egress не запускает retune, ротацию или покупку прокси.

## Проверки

- public и canonical: **1202 tests, OK (skipped=3)**; platform-specific Linux-проверки пропущены только на Windows;
- каждый логический шаг прошёл независимую проверку;
- Python compile, shell/JSON syntax, public secret scan, canonical/public mirror и `git diff --check` — PASS;
- локальный canary на VADIM: штатный `UPDATE=1` завершился с `rc=0`, Linux-фокус
  policy-route/DNS/setup — **77/77**, полный `vpn_healthcheck.py ru` — PASS;
  DNS Rescue сохранил `idle` без операций/правил, а exact rule/default/marked FIB
  остались корректны после рестарта `sing-box` и нескольких watchdog-тиков.
  `/opt/redut-src` синхронизирован с принятым кандидатом, а отдельное проверенное
  дерево отката 1.13.0 сохранено без изменений;
- публикация в GitHub отложена по решению владельца: push/tag/release не выполнялись.
  Перед будущей публикацией то же дерево должно пройти release-candidate CI и
  финальную проверку release-скриптом.
