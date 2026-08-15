#!/bin/bash
# setup.sh — установка узла «Редут» ОДНОЙ КОМАНДОЙ прямо на сервере.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/Enjoyment005/redut/main/setup.sh)
#
# Скрипт рассчитан на чистую Debian 13 и запуск от root. Он скачивает репозиторий,
# ставит базу (WireGuard, sing-box, маршруты, самолечение) и веб-панель, после чего
# печатает адрес мастера первого входа.
#
# Почему `bash <(curl …)`, а не `curl … | bash`: при пайпе у скрипта нет stdin, и он
# не может ничего спросить у человека. Здесь stdin остаётся терминалом.
#
# Идемпотентно: повторный запуск обновляет узел, не теряя ключи, клиентов и учётку панели.
#
# Переменные окружения (все необязательные):
#   REPO=владелец/имя    другой репозиторий (по умолчанию — официальный, см. ниже)
#   BRANCH=main          ветка
#   NAME=node1           имя узла
#   PANEL_PORT=8443      порт веб-панели
#   SUBNET=10.8.0.0/24   клиентская подсеть
#   CLIENTS=phone1       клиенты через запятую (или число: client1..N)
set -euo pipefail

REPO="${REPO:-Enjoyment005/redut}"
BRANCH="${BRANCH:-main}"
NAME="${NAME:-node1}"
PANEL_PORT="${PANEL_PORT:-8443}"
SUBNET="${SUBNET:-10.8.0.0/24}"
CLIENTS="${CLIENTS:-phone1}"
WORKDIR="/opt/redut-src"

say()  { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32m✔\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

# ── 0. Проверки окружения ───────────────────────────────────────────────────
say "Проверяю сервер"
[ "$(id -u)" = "0" ] || die "нужен root: запусти через sudo -i или от root"
[ -r /etc/os-release ] || die "не похоже на Linux с /etc/os-release"
. /etc/os-release
[ "${ID:-}" = "debian" ] || die "нужен Debian (у тебя: ${PRETTY_NAME:-неизвестно}). Установщик проверялся на Debian 13."
case "${VERSION_ID:-}" in
    13*) ok "Debian ${VERSION_ID} — то, что нужно" ;;
    *)   printf '  \033[1;33m!\033[0m Debian %s вместо 13 — не проверялось, продолжаю на свой страх\n' "${VERSION_ID:-?}" ;;
esac
[ "$(uname -m)" = "x86_64" ] || die "нужна архитектура x86_64 (у тебя $(uname -m))"
command -v systemctl >/dev/null || die "нет systemd"
ip route show default | grep -q . || die "нет маршрута по умолчанию — сервер без сети?"
ok "root, systemd, сеть на месте"

# ── 1. Минимальные зависимости для самой установки ──────────────────────────
say "Ставлю curl/tar/python3 (если их нет)"
export DEBIAN_FRONTEND=noninteractive
missing=""
for p in curl tar python3; do command -v "$p" >/dev/null || missing="$missing $p"; done
if [ -n "$missing" ]; then
    apt-get update -qq >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    apt-get install -y -qq $missing >/dev/null || die "не поставить:$missing"
fi
ok "curl, tar, python3 готовы"

# ── 2. Исходники ────────────────────────────────────────────────────────────
# SRC_DIR — уже распакованный репозиторий (склонировали руками / копия на диске).
# Тогда ничего не качаем: удобно без интернета к GitHub и при доработке скрипта.
SRC_DIR="${SRC_DIR:-}"
if [ -z "$SRC_DIR" ] && [ -f "$(dirname "$0")/install/install.sh" ]; then
    SRC_DIR="$(cd "$(dirname "$0")" && pwd)"      # запущен из корня репозитория
fi
if [ -n "$SRC_DIR" ]; then
    say "Использую локальные исходники: $SRC_DIR"
    [ -f "$SRC_DIR/install/install.sh" ] || die "в $SRC_DIR нет install/install.sh"
    WORKDIR="$SRC_DIR"
else
    say "Скачиваю Редут ($REPO, ветка $BRANCH)"
    rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"
    url="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
    if ! curl -fsSL "$url" | tar -xz -C "$WORKDIR" --strip-components=1; then
        die "не скачался $url — проверь имя репозитория (REPO=владелец/имя) и ветку"
    fi
    [ -f "$WORKDIR/install/install.sh" ] || die "в архиве нет install/install.sh — не тот репозиторий?"
fi
ok "исходники в $WORKDIR"

# ── 3. Параметры узла ───────────────────────────────────────────────────────
say "Определяю сетевые параметры"
cd "$WORKDIR"
python3 - "$NAME" "$SUBNET" "$CLIENTS" <<'PY' > "$WORKDIR/install/params.sh"
import os, re, subprocess, sys
sys.path.insert(0, "install")
import profiles

name, subnet, clients_spec = sys.argv[1], sys.argv[2], sys.argv[3]

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

route = sh("ip route show default")
m = re.search(r"default via (\S+) dev (\S+)", route)
if not m:
    sys.exit("не определить шлюз/интерфейс")
gw, wan = m.group(1), m.group(2)
server_ip = sh("ip -4 -o addr show dev %s scope global | awk '{print $4}' | cut -d/ -f1 | head -1" % wan)

base = subnet.split("/")[0].rsplit(".", 1)[0]
if re.fullmatch(r"\d+", clients_spec):
    names = ["client%d" % i for i in range(1, int(clients_spec) + 1)]
else:
    names = [x.strip() for x in clients_spec.split(",") if x.strip()]
# Элемент можно задать как "имя" (адрес назначится сам) или "имя:10.8.0.5" —
# точный адрес нужен при переустановке поверх живого узла, чтобы у клиента не
# поменялся IP и его старый профиль продолжил работать.
clients = []
for i, n in enumerate(names):
    if ":" in n:
        nm, addr = n.split(":", 1)
        clients.append({"name": nm.strip(), "addr": addr.strip()})
    else:
        clients.append({"name": n, "addr": "%s.%d" % (base, 2 + i)})

# Имя базового профиля не хардкодим: в разных сборках оно своё, а нам нужны лишь
# его дефолты (порт wg, версия sing-box, параметры локального SOCKS).
profile_name = os.environ.get("PROFILE") or sorted(profiles.PROFILES)[0]
p = profiles.build_profile(profile_name, server_ip, "", {"subnet": subnet})
p["name"], p["role"], p["clients"] = name, "vpn-%s" % name, clients
sys.stdout.write(profiles.render_params(p, {"gw": gw, "wan": wan, "server_ip": server_ip}))
PY
chmod 600 "$WORKDIR/install/params.sh"
grep -E '^(SERVER_IP|WAN|GW|SUBNET|CLIENTS)=' "$WORKDIR/install/params.sh" | sed 's/^/  /'
ok "параметры готовы"

# ── 4. База: WireGuard, sing-box, маршруты, самолечение ─────────────────────
say "Ставлю базу узла (это самый долгий шаг, пара минут)"
bash "$WORKDIR/install/install.sh" 2>&1 | sed 's/^/  /'

# сторож самолечения (в публичной раскладке лежит в node/)
if [ -f "$WORKDIR/node/singbox-watchdog.sh" ]; then
    install -m 0755 "$WORKDIR/node/singbox-watchdog.sh" /usr/local/bin/singbox-watchdog.sh
    ok "сторож самолечения установлен"
fi

# ── 5. Агент и веб-панель ───────────────────────────────────────────────────
say "Ставлю агента и веб-панель"
out="$(python3 "$WORKDIR/install/setup_panel.py" --src "$WORKDIR/agent" \
        --name "$NAME" --port "$PANEL_PORT" --subnet "$SUBNET")"
echo "$out" | grep -v '^{' | sed 's/^/  /' || true
json="$(echo "$out" | tail -1)"
SERVER_IP="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('server_ip',''))" "$json")"
CERT_FP="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('cert_fp',''))" "$json")"
FRESH="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('fresh_setup'))" "$json")"

# ── 6. Проверка ─────────────────────────────────────────────────────────────
say "Проверяю, что всё поднялось"
fail=0
for s in wg-quick@wg0 sing-box vpn-boot-setup vpn-panel; do
    st="$(systemctl is-active "$s" 2>/dev/null || true)"
    if [ "$st" = "active" ]; then ok "$s"; else printf '  \033[1;31m✖\033[0m %s: %s\n' "$s" "$st"; fail=1; fi
done
hz="$(curl -sk --max-time 10 "https://127.0.0.1:${PANEL_PORT}/healthz" || true)"
[ "$hz" = "ok" ] && ok "панель отвечает" || { printf '  \033[1;31m✖\033[0m панель не отвечает\n'; fail=1; }

# ── 7. Итог ─────────────────────────────────────────────────────────────────
printf '\n\033[1;36m══════════════════════════════════════════════════════════\033[0m\n'
if [ "$fail" = "0" ]; then
    printf '\033[1;32m  Узел «Редут» готов\033[0m\n'
else
    printf '\033[1;33m  Узел поднят с замечаниями — смотри отметки выше\033[0m\n'
fi
printf '\033[1;36m══════════════════════════════════════════════════════════\033[0m\n\n'
if [ "$FRESH" = "True" ]; then
    printf '  Открой в браузере и пройди мастер первого входа:\n\n'
    printf '      \033[1;97mhttps://%s:%s/setup\033[0m\n\n' "$SERVER_IP" "$PANEL_PORT"
    printf '  \033[1;33mВАЖНО:\033[0m первый вход не защищён паролем — панель займёт тот,\n'
    printf '  кто откроет её первым. Пройди мастер сразу.\n\n'
else
    printf '  Панель уже настроена: https://%s:%s/\n\n' "$SERVER_IP" "$PANEL_PORT"
fi
printf '  Сертификат самоподписанный, браузер предупредит. Сверь отпечаток:\n'
printf '      %s\n\n' "$CERT_FP"
printf '  Профили устройств выдаются в панели: раздел «Кто подключён» →\n'
printf '  имя устройства → «Выдать доступ» → QR для телефона или файл для компьютера.\n\n'
printf '  Клиентские конфиги на сервере: /etc/wireguard/clients/\n'
printf '  Повторный запуск этой команды безопасен — узел обновится, ключи сохранятся.\n\n'
