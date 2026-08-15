# -*- coding: utf-8 -*-
"""vpn-panel — веб-морда над vpn-agent (stdlib, без pip-зависимостей).

Фаза 4 (частично): статус, пул с ролями, probe/apply/rollback, журнал.
Аутентификация: пароль (scrypt) + TOTP + recovery-коды, антибрут, CSRF.
Деньги (buy/prolong/delete) — заглушка до Фазы 2.
"""
