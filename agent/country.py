# -*- coding: utf-8 -*-
"""country.py — политика стран: чёрный список (никогда) + умная оценка остальных.

Решение владельца 2026-08-15. Раньше действовал жёсткий белый список: покупать
разрешалось только из 17 перечисленных стран, а весь СНГ был захардкожен в блок.
Теперь правило другое:

  * **чёрный список — навсегда**: Россия, Украина, Беларусь. Оттуда никогда не
    покупаем и такой выход не используем (для обхода блокировок он бессмыслен,
    да и юридически это не то, что нужно). Список можно только РАСШИРИТЬ через
    `config['countries']['blacklist']`, сузить — нельзя (предохранитель в коде);
  * **все прочие страны разрешены**, но получают оценку. Она складывается из
    репутации страны у сервисов и из того, **сходятся ли geoip-базы** в её
    определении. Оценка идёт добавкой к скорингу пробы (§7.4) — значит при прочих
    равных автоматика сама выберет Латвию, а не Нигерию, но человек волен
    применить любой прокси вне чёрного списка.

Почему репутация вообще важна (случай 2026-08-15): прокси `203.0.113.77` продан
как нигерийский, ip-api видит Нигерию, ipinfo — Нью-Йорк. Для сайта это «страна
скачет» — типовая реакция антифрода: капчи, отказ оплаты, требование верификации.
Технически прокси исправен, поэтому дисквалифицировать его нельзя — но и выбирать
его первым, когда рядом есть Рига, не нужно. Ровно это и делает оценка.

Модуль намеренно без зависимостей: его импортируют probe (скоринг), money (гейт
покупки), agent/states (авто-подбор страны) и webpanel (объяснения в интерфейсе).
"""

# ── 1. Чёрный список: никогда, ни покупать, ни использовать ────────────────
# Копии этой константы держат probe.HARD_BLOCK_CC и providers.base.HARD_BLOCK_CC
# (независимые предохранители на разных слоях); tests/test_provider_money.py
# сверяет, что они не разошлись.
BLACKLIST_CC = frozenset({"ru", "ua", "by"})

# ── 2. Репутация страны у сервисов (банки, платёжки, магазины, антифрод) ───
# Оценка — не «хорошая/плохая страна», а вероятность лишних проверок на выходе.
TRUSTED_CC = frozenset({          # ЕС/ЕЭЗ + Швейцария, Британия, США, Канада
    "fi", "ee", "lv", "lt", "se", "no", "dk", "is", "de", "nl", "be", "lu",
    "at", "ch", "ie", "gb", "fr", "it", "es", "pt", "pl", "cz", "sk", "si",
    "hr", "hu", "ro", "bg", "gr", "mt", "cy", "us", "ca"})
GOOD_CC = frozenset({             # прочие развитые: репутация ровная, но дальше
    "jp", "kr", "sg", "hk", "tw", "au", "nz", "il", "ae", "qa", "uy", "cl"})
LOW_TRUST_CC = frozenset({        # чаще всего ловят капчи/отказы оплаты
    # соседи РФ — до 2026-08-15 были в жёстком блоке, теперь просто низкий рейтинг
    "kz", "kg", "tj", "uz", "tm", "am", "az", "md", "ge",
    # регионы, которые антифрод исторически считает высокорисковыми
    "ng", "gh", "ke", "cm", "ci", "sn", "tz", "ug", "zw", "za",
    "id", "vn", "ph", "bd", "pk", "in", "lk", "np", "mm", "kh", "la",
    "br", "mx", "ve", "co", "pe", "bo", "py", "ec", "gt", "hn", "ni", "do", "ht", "jm",
    "iq", "ir", "sy", "af", "ye", "ly", "sd", "so", "tr", "eg", "ma", "dz", "tn"})

RATING_TRUSTED = 25
RATING_GOOD = 12
RATING_NEUTRAL = 0
RATING_LOW = -25
GEO_MISMATCH_PENALTY = -20   # geoip-базы разошлись: для сайтов «страна скачет»
MIN_AUTO_RATING = 0          # ниже — автоматика сама не покупает (человек может)


def norm(cc):
    return (str(cc or "").strip().lower() or None)


def blacklist(cfg=None):
    """Чёрный список: код + необязательное расширение из конфига. Только РАСШИРЯЕТ."""
    extra = ((cfg or {}).get("countries") or {}).get("blacklist") or []
    return set(BLACKLIST_CC) | {c for c in (norm(x) for x in extra) if c}


def is_blocked(cc, cfg=None):
    c = norm(cc)
    return bool(c) and c in blacklist(cfg)


def rating(cc, geo_agree=True, cfg=None):
    """Оценка страны: None — запрещена, иначе число (больше = меньше проблем).

    geo_agree=False — базы geoip разошлись в определении страны этого IP.
    Неизвестная страна (None) — нейтральна: незнание не повод ни блокировать,
    ни поощрять.
    """
    c = norm(cc)
    if c and c in blacklist(cfg):
        return None
    if c is None:
        base = RATING_NEUTRAL
    elif c in TRUSTED_CC:
        base = RATING_TRUSTED
    elif c in GOOD_CC:
        base = RATING_GOOD
    elif c in LOW_TRUST_CC:
        base = RATING_LOW
    else:
        base = RATING_NEUTRAL
    return base + (0 if geo_agree else GEO_MISMATCH_PENALTY)


def auto_allowed(cc, geo_agree=True, cfg=None):
    """Может ли автоматика САМА купить прокси в этой стране."""
    r = rating(cc, geo_agree, cfg)
    return r is not None and r >= MIN_AUTO_RATING


def tier(cc, geo_agree=True, cfg=None):
    """Короткая метка для интерфейса и журнала."""
    r = rating(cc, geo_agree, cfg)
    if r is None:
        return "blocked"
    if not geo_agree:
        return "disputed"
    if r >= RATING_TRUSTED:
        return "trusted"
    if r >= RATING_GOOD:
        return "good"
    if r <= RATING_LOW:
        return "risky"
    return "neutral"


def explain(cc, geo_agree=True, cfg=None):
    """Человеческое объяснение — идёт в подсказку панели и в причину отказа."""
    c = norm(cc)
    t = tier(c, geo_agree, cfg)
    if t == "blocked":
        return "страна в чёрном списке — не покупаем и не используем никогда"
    if t == "disputed":
        return ("geoip-базы расходятся в определении страны этого IP — для сайтов "
                "«страна скачет», это лишние капчи и проверки оплаты")
    if t == "trusted":
        return "надёжная страна выхода: Европа/США — минимум лишних проверок"
    if t == "good":
        return "нормальная страна выхода, но дальше от РФ — выше задержка"
    if t == "risky":
        return ("страна с высоким риском отказов: банки, платёжки и магазины "
                "часто требуют доп. подтверждения или блокируют оплату")
    return "нейтральная страна: явных проблем не известно"


def rank(candidates, cfg=None):
    """Отсортировать коды стран по убыванию оценки; запрещённые — выбросить.

    Порядок внутри одной оценки сохраняется входной (у вызывающего он осмысленный:
    например, «предпочитаемые» страны из конфига идут по возрастанию задержки).
    """
    out = []
    for i, cc in enumerate(candidates or []):
        c = norm(cc)
        r = rating(c, True, cfg)
        if r is None:
            continue
        out.append((-r, i, c))
    return [c for _, _, c in sorted(out)]
