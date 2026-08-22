# -*- coding: utf-8 -*-
"""Интеграционные READ-ONLY тесты с реальными ключами (сеть, деньги не тратятся).

Вызовы: list + balance у обоих провайдеров, check?ids= у PROXY6.
НИКОГДА не вызывается: buy/prolong/delete/renew/ipauth/setdescr.
Ошибка 105 (Error ip — ограничение API по IP в кабинете) — внятное сообщение, не падение.

Запуск:  python tests/integration_readonly.py
Ключи:   /etc/vpn-panel/secrets.json либо ../.secrets.local.json
"""
import sys

import _ctx  # noqa: F401  (sys.path)
import agent
from providers import make_providers, ProviderError


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    secrets, src = agent.load_secrets()
    providers = make_providers(secrets)
    if not providers:
        print("Ключей нет (%s) — интеграционные тесты пропущены" % (src or "secrets не найден"))
        return 0
    print("Ключи: %s (провайдеры: %s)" % (src, ", ".join(providers)))
    failures = 0

    for name, prov in providers.items():
        print("\n=== %s ===" % name)
        try:
            items = prov.list()
            print("list: %d активных прокси" % len(items))
            for it in items[:10]:
                print("  %s:%s  %s  s5=%s http=%s  cc=%s  до %s  descr=%r"
                      % (it["provider"], it["ext_id"], it["host"],
                         it["port_socks5"] or "—", it["port_http"] or "—",
                         it["country"], it["date_end"][:10], it["descr"]))
            if len(items) > 10:
                print("  … и ещё %d" % (len(items) - 10))
        except ProviderError as e:
            failures += 1
            if getattr(e, "code", None) == 105:
                print("list: ⚠️ ошибка 105 — доступ к API PROXY6 ограничен по IP.\n"
                      "  Решение: в кабинете PROXY6 добавить текущий IP (и IP серверов\n"
                      "  203.0.113.10, 203.0.113.11) в список разрешённых, либо снять ограничение.")
            else:
                print("list: ОШИБКА — %s" % e)
            continue
        try:
            b = prov.balance()
            print("balance: %s %s" % (b.get("balance"), b.get("currency")))
        except ProviderError as e:
            failures += 1
            print("balance: ОШИБКА — %s" % e)
        if prov.caps.get("check") and items:
            ext = items[0]["ext_id"]
            try:
                alive = prov.check(ext)
                print("check?ids=%s -> %s" % (ext, alive))
            except ProviderError as e:
                failures += 1
                print("check: ОШИБКА — %s" % e)
    print("\nИтог: %s" % ("OK" if failures == 0 else "%d ошибок" % failures))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
