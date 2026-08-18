# -*- coding: utf-8 -*-
"""alerts.py — письма-алерты агента (§8/§10, §20 п.7). Только stdlib (smtplib).

Настройки SMTP — в secrets.json, блок "smtp" (0600 на сервере, §13):
    {"smtp": {"host": "mail.example.com", "port": 587,
              "user": "node@example.com", "password": "…",
              "from": "node@example.com", "to": "owner@example.com"}}
port 465 -> SMTPS (SSL), иначе STARTTLS (обычно 587).

Философия: письмо — ВТОРИЧНО по отношению к ротации. SMTP не настроен, сервер
недоступен, отправка упала — НИКОГДА не роняем вызывающего: возвращаем False и
пишем причину в log-callback. Иначе сбой почты заблокировал бы восстановление сети.

Частоту писем регулирует ВЫЗЫВАЮЩИЙ (states.py): напр., про EMERGENCY письмо шлётся
один раз при входе в режим, а не на каждую повторную попытку раз в 15 мин. Здесь —
только форматирование и отправка.

Секреты (ключи провайдеров) в теле письма маскируются переданным mask-callable —
у PROXY6 ключ лежит в пути URL, светить его в почте нельзя (§15).
"""
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, formataddr

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(x):
    """Грубая проверка «это вообще e-mail?»: есть @ и точка в домене, без пробелов."""
    return bool(_EMAIL_RE.match((x or "").strip()))


def _stderr(msg):
    import sys
    print("[alerts] %s" % msg, file=sys.stderr)


class Alerter:
    """Отправитель писем. Все typed-методы возвращают bool (отправлено/нет)."""

    def __init__(self, smtp=None, server="srv", log=None, mask=None, timeout=20):
        self.smtp = smtp or {}
        self.server = server or "srv"
        self.log = log or _stderr
        self.mask = mask or (lambda s: s)
        self.timeout = timeout
        self.last_error = ""              # почему не ушло последнее письмо (для мастера)

    @property
    def configured(self):
        """Есть ли чем и куда слать. «from» НЕ обязателен: _send подставит логин SMTP
        (реальный ящик) — тем же фолбэком, что и при ярлыке вместо адреса. Раньше
        пустой «from» молча выключал ВСЕ алерты, хотя ящик настроен и письма ушли бы:
        поймано на node2 18.08 (мастер сохранил from="" -> «SMTP не настроен»).
        Условие теперь совпадает с тем, что _send реально умеет отправить."""
        s = self.smtp
        return bool(s and s.get("host") and s.get("to")
                    and (_valid_email(s.get("from")) or _valid_email(s.get("user"))))

    # ------------------------------------------------------------- транспорт
    def _send(self, subject, body):
        """Собрать и отправить письмо. Любой сбой -> False (не бросаем)."""
        self.last_error = ""
        if not self.configured:
            self.last_error = "почта не настроена"
            self.log("SMTP не настроен — письмо «%s» не отправлено (это не ошибка)" % subject)
            return False
        s = self.smtp
        subj = "[vpn-agent %s] %s" % (self.server, subject)
        try:
            body = self.mask(body)
            # Envelope-from обязан быть НАСТОЯЩИМ адресом. Если оператор вписал в поле
            # «from» отображаемое имя («От ВПНА»), а не e-mail, SMTP отклонит письмо
            # (501 Invalid MAIL FROM) и все алерты молча пропадут. Берём валидный адрес:
            # сам «from», иначе — логин SMTP (это реальный ящик). Ярлык оператора при
            # этом сохраняем как display-name, чтобы подпись в письме не потерялась.
            raw_from = (s.get("from") or "").strip()
            login = (s.get("user") or "").strip()
            if _valid_email(raw_from):
                from_hdr = raw_from
            elif _valid_email(login):
                from_hdr = formataddr((raw_from, login)) if raw_from else login
            else:
                self.last_error = "нет адреса, с которого слать"
                self.log("SMTP from-адрес «%s» невалиден, а валидного user для подмены нет "
                         "— письмо «%s» не отправлено (это не ошибка)" % (raw_from, subject))
                return False
            msg = EmailMessage()
            msg["Subject"] = subj
            msg["From"] = from_hdr
            msg["To"] = s["to"]
            msg["Date"] = formatdate(localtime=True)
            msg.set_content(body)
            port = int(s.get("port") or 587)
            host = s["host"]
            if port == 465:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(host, port, timeout=self.timeout, context=ctx) as srv:
                    if s.get("user"):
                        srv.login(s["user"], s.get("password") or "")
                    srv.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=self.timeout) as srv:
                    srv.ehlo()
                    try:
                        srv.starttls(context=ssl.create_default_context())
                        srv.ehlo()
                    except smtplib.SMTPException:
                        pass  # сервер без STARTTLS — шлём как есть (внутренняя почта)
                    if s.get("user"):
                        srv.login(s["user"], s.get("password") or "")
                    srv.send_message(msg)
            self.log("письмо отправлено: %s -> %s" % (subj, s["to"]))
            return True
        except Exception as e:
            # Маскируем и текст ошибки: в него мог попасть логин/хост.
            self.last_error = self.mask(str(e))
            self.log("НЕ удалось отправить письмо «%s»: %s" % (subject, self.last_error))
            return False

    def send(self, subject, body):
        """Низкоуровневая отправка (для нестандартных случаев)."""
        return self._send(subject, body)

    # ------------------------------------------------------- типовые события
    def rotated(self, *, old_ip, new_ip, uid, egress, cc, tg_code, score=None, candidates_tried=None):
        # Холодный старт (канал ещё не выбирался): old_ip пуст — пишем это словами, а не пустотой
        # (письмо «Ротация upstream:  -> X» выглядело как обрыв строки; приёмка 15.08).
        first = not old_ip
        was = old_ip or "канала не было (первый выбор)"
        body = (
            ("Первый исходящий канал выбран автоматически (§8 ROTATING).\n\n" if first
             else "Upstream-прокси заменён автоматически (§8 ROTATING).\n\n")
            + "  было:   %s\n  стало:  %s  (%s)\n"
            "  выход:  %s  страна=%s  telegram=%s\n"
            "%s"
            % (was, new_ip, uid, egress, cc or "?", tg_code or "?",
               ("  перебрано кандидатов: %s\n" % candidates_tried) if candidates_tried else "")
            + ("Узел вышел из прямого выхода на канал из пула. Действий не требуется." if first
               else "Реакция на смерть прежнего upstream. Действий не требуется."))
        subject = ("Первый канал: %s" % new_ip) if first else ("Ротация upstream: %s -> %s" % (old_ip, new_ip))
        return self._send(subject, body)

    def retuned(self, *, host, old_mode, new_mode, uid=None):
        body = (
            "Смена протокола без смены IP (§7.3 RETUNE).\n\n"
            "  прокси: %s  %s\n"
            "  было:   %s\n  стало:  %s\n\n"
            "Провайдер прикрыл один протокол, второй жив — IP не менялся, "
            "перелогины/капчи не потребуются. Ротации не было."
            % (host, uid or "", old_mode, new_mode))
        return self._send("RETUNE (%s): %s -> %s" % (host, old_mode, new_mode), body)

    def bought(self, *, uid, price, currency, balance_after, country, period,
               egress=None, cc=None, recovered=False):
        body = (
            "Докуплен прокси взамен кончившегося пула (§8 REPLENISH).\n\n"
            "  прокси:  %s\n  страна:  %s,  период %s дн\n"
            "  цена:    %s %s\n  баланс:  %s %s (после покупки)\n"
            "  выход:   %s  страна=%s\n%s"
            % (uid, country, period, price, currency, balance_after, currency,
               egress or "проба идёт", cc or "?",
               "  ВНИМАНИЕ: покупка ВОССТАНОВЛЕНА по descr после обрыва сети.\n" if recovered else ""))
        return self._send("Покупка прокси: %s %s (%s)" % (price, currency, country), body)

    def prolonged(self, *, uid, days, price, currency, balance_after, date_end, cc=None):
        body = (
            "Боевой прокси продлён автоматически (§6.3, «якорь»).\n\n"
            "  прокси:  %s%s\n  срок:    +%s дн, теперь до %s\n"
            "  цена:    %s %s\n  баланс:  %s %s (после списания)\n\n"
            "IP не менялся — перелогины, капчи и подтверждения клиентам не грозят. "
            "В этом и смысл: прогретый адрес дороже нового."
            % (uid, (" (%s)" % cc) if cc else "", days, date_end or "?",
               price, currency, balance_after, currency))
        return self._send("Продление: %s %s (%s дн)" % (price, currency, days), body)

    def prolong_failed(self, *, uid, days_left, reason):
        body = (
            "⚠️ НЕ УДАЛОСЬ продлить боевой прокси — он скоро истечёт.\n\n"
            "  прокси:  %s\n  осталось: %s дн\n  причина: %s\n\n"
            "Что будет, если ничего не сделать: адрес отключится у провайдера, выход умрёт, "
            "и автоматика начнёт искать замену — то есть ты получишь НОВЫЙ, непрогретый IP "
            "(перелогины, капчи, проверки оплаты).\n\n"
            "Что сделать: пополнить баланс / поднять лимиты в /etc/vpn-panel/config.json "
            "или продлить руками кнопкой «Продлить» в панели."
            % (uid, days_left, reason))
        return self._send("Продление НЕ прошло — прокси истекает (%s дн)" % days_left, body)

    def blocked_cc(self, *, uid, cc):
        body = ("Купленный прокси %s вышел в СНГ/РФ (реальная страна=%s, жёсткий блок §6.1).\n"
                "Помечен off, в работу не взят. Проверь метку страны у провайдера."
                % (uid, cc))
        return self._send("Купленный прокси вышел в блок (%s)" % cc, body)

    def emergency(self, *, reason):
        body = (
            "⛔ АВАРИЙНЫЙ РЕЖИМ (§8 EMERGENCY).\n\n"
            "Живых кандидатов нет и купить нельзя:\n  %s\n\n"
            "Трафик клиентов переключён на ПРЯМОЙ выход через WAN сервера "
            "(вместо чёрной дыры в мёртвый tun0). Это НЕ обход блокировок — "
            "YouTube/Google из РФ снова недоступны, но связь у клиентов есть.\n\n"
            "Агент повторяет попытку восстановиться с нарастающим интервалом "
            "(2 → 5 → 10 → 15 → 30 минут). Разберись с причиной (баланс/лимиты/"
            "провайдер) — по восстановлении автомат сам вернётся в обычный режим." % reason)
        return self._send("АВАРИЙНЫЙ РЕЖИМ — прямой выход через WAN", body)

    def tg_degraded(self, *, streak, egress=None):
        body = (
            "⚠️ Канал жив, но api.telegram.org недоступен (%d проверок подряд).\n\n"
            "  выход (ipify через tun0): %s — работает\n\n"
            "Ротацию НЕ делаю: сам прокси жив, менять его из-за чужого сбоя — терять "
            "прогретый IP. У клиентов может не работать Telegram; остальной интернет цел.\n"
            "Если Telegram важен и не оживает — попробуй «Ротация» в панели вручную."
            % (streak, egress or "?"))
        return self._send("Telegram недоступен, канал жив (DEGRADED)", body)

    def recovered(self, *, new_ip, egress, cc):
        body = ("Аварийный режим снят — найден рабочий upstream.\n\n"
                "  upstream: %s\n  выход:    %s  страна=%s\n\n"
                "Трафик снова идёт через прокси. Действий не требуется."
                % (new_ip, egress, cc or "?"))
        return self._send("Выход из аварийного режима", body)

    def provider_switched(self, *, provider, old_ip, new_ip, uid, egress, cc):
        body = (
            "Ключ провайдера %s удалён — боевой канал переехал к другому провайдеру (П7-2).\n\n"
            "  было:   %s  (%s, управлять им больше нечем)\n"
            "  стало:  %s  (%s)\n"
            "  выход:  %s  страна=%s\n\n"
            "Кандидата выбрала текущая стратегия, переключение прошло с проверкой "
            "и автооткатом. Прокси удалённого провайдера убраны из пула. Действий не требуется."
            % (provider, old_ip, provider, new_ip, uid, egress, cc or "?"))
        return self._send("Канал переключён: ключ %s удалён" % provider, body)

    def provider_switch_stuck(self, *, provider, host, tried=0):
        body = (
            "⚠️ Ключ провайдера %s удалён, но боевой канал ПОКА ОСТАЁТСЯ на его прокси %s: "
            "живых кандидатов у оставшихся провайдеров не нашлось (перебрано %s).\n\n"
            "Канал работает, но продлить его НЕЧЕМ — когда срок аренды выйдет, выход умрёт "
            "и автоматика начнёт искать замену уже по-аварийному.\n\n"
            "Что сделать: проверь пул в панели (живы ли прокси второго провайдера), докупи "
            "или дождись — панель сама повторяет попытку переключения при каждом обновлении "
            "пула (каждые полчаса)." % (provider, host, tried or "0"))
        return self._send("Боевой канал остался у провайдера без ключа", body)

    def pool_empty(self, *, detail=""):
        body = ("Пул проверенных кандидатов кончился — все off/gone/на cooldown.\n"
                "%s\nПопытка докупить (REPLENISH) — по лимитам §6.2." % detail)
        return self._send("Пул прокси кончился", body)

    def no_funds(self, *, detail=""):
        body = ("Не хватило денег на покупку прокси (§6.2/§10).\n  %s\n\n"
                "Покупка НЕ выполнена, агент ушёл в аварийный режим. Пополни баланс PROXY6." % detail)
        return self._send("Денег не хватило — пополни баланс", body)

    def api_105(self, *, detail=""):
        body = ("PROXY6 отклоняет вызовы с этого сервера: ошибка 105 (неверный IP).\n  %s\n\n"
                "Покупка недоступна, работаем на кэше пула. Добавь IP сервера в "
                "ограничение API в кабинете PROXY6." % detail)
        return self._send("PROXY6 105 — добавь IP сервера в кабинет", body)

    def no_market(self, *, detail=""):
        body = ("Нет прокси version=4 в наличии ни в одной стране белого списка (§6.1).\n  %s\n\n"
                "Покупка не выполнена. Возможно, стоит расширить белый список стран." % detail)
        return self._send("Нет прокси в наличии у провайдера", body)

    def frozen_net(self, *, detail=""):
        body = ("Сеть самого сервера недоступна (§8 FROZEN_NET): прямой запрос мимо прокси "
                "не проходит.\n  %s\n\nАгент НИЧЕГО не меняет и НЕ покупает — иначе обрыв у "
                "хостера сжёг бы пул и накупил прокси. Жду восстановления сети." % detail)
        return self._send("Сеть сервера легла — автоматика заморожена", body)

    def no_heartbeat(self, *, hours, last_ts=""):
        body = ("Агент не отчитывался об успешном цикле более %.0f часов (последний: %s).\n\n"
                "Возможно, cron/агент умер — тогда прокси не продлеваются и молча истекут (§6.3). "
                "Проверь сервер: `vpn-agent status`." % (hours, last_ts or "неизвестно"))
        return self._send("Агент молчит >%.0f ч — проверь пульс" % hours, body)


def make_alerter(secrets, cfg, log=None, mask=None):
    """Собрать Alerter из secrets['smtp'] + метки сервера из cfg."""
    smtp = (secrets or {}).get("smtp") or {}
    return Alerter(smtp=smtp, server=(cfg or {}).get("server") or "srv", log=log, mask=mask)
