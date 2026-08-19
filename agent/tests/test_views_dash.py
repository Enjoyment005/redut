# -*- coding: utf-8 -*-
"""Вёрстка дашборда: инварианты, которые ломались молча (19.08).

1) Справочные разделы (details «что делает каждая кнопка» / «если интернет
   пропал») обязаны открываться и при «Объяснения: выкл»: их содержимое —
   .ex, а body.noex .ex прячет все .ex подряд — нужна CSS-оговорка, причём
   ПОСЛЕ прячущего правила (каскад).
2) Паспорт IP на карте: блок и его загрузчик должны присутствовать в дашборде —
   исчезнут при рефакторинге, и оверлей молча пропадёт.
"""
import unittest

from _ctx import PANEL_DIR  # noqa: F401 — панель в sys.path
from webpanel import views


class TestHelpDetailsVisibleWithoutEx(unittest.TestCase):
    def test_css_exception_present_and_after_hider(self):
        css = views._BASE_CSS
        hide = css.find("body.noex .ex{display:none}")
        show = css.find("body.noex details .ex{display:block}")
        self.assertGreater(hide, -1, "правило-прятальщик .ex пропало — тест устарел?")
        self.assertGreater(show, -1, "нет CSS-оговорки: справка в details откроется пустой "
                                     "при выключенных «Объяснениях»")
        self.assertGreater(show, hide, "оговорка должна идти ПОСЛЕ прячущего правила, "
                                       "иначе каскад оставит display:none")

    def test_help_sections_exist(self):
        html = views._DASH_HTML
        self.assertIn("Справка: что делает каждая кнопка", html)
        self.assertIn("Что делать, если интернет у клиентов пропал", html)


class TestMapIntelMarkup(unittest.TestCase):
    def test_intel_block_and_loader_present(self):
        html = views._DASH_HTML
        self.assertIn('id="geointel"', html)
        self.assertIn("/api/ipinfo", html)
        self.assertIn("function intelHtml", html)
        # оверлей позиционируется поверх карты справа
        self.assertIn(".geo .intel{position:absolute;right:", views._BASE_CSS)


class TestVitalsMarkup(unittest.TestCase):
    """Строка «Сервер» в шапке (1.8.0): блок, рендерер и стили обязаны быть —
    пропадут при рефакторинге, и показатели молча исчезнут. Владелец просил
    ОБЫЧНЫЙ ТЕКСТ в стиле подстроки шапки, а не карточки (19.08)."""

    def test_vitals_line_present(self):
        html = views._DASH_HTML
        self.assertIn('id="vitals"', html)
        self.assertIn("function vitals", html)
        self.assertIn("s.sys", html)              # данные — из /api/status
        self.assertIn(".vitals{", views._BASE_CSS)
        # текстовая строка, а не плитки: карточных классов быть не должно
        self.assertNotIn(".vit{", views._BASE_CSS)
        self.assertNotIn(".vbar", views._BASE_CSS)
        self.assertIn("советуем ≤", html)

    def test_vitals_wired_into_both_loaders(self):
        # вызовы из loadStatus И loadClients: рекомендация зависит и от железа,
        # и от числа выданных профилей — кто пришёл последним, тот и дорисовал
        html = views._DASH_HTML
        self.assertGreaterEqual(html.count("vitals();clientRec()"), 2)

    def test_clients_recommendation_present(self):
        html = views._DASH_HTML
        self.assertIn('id="crec"', html)
        self.assertIn("function clientRec", html)
        self.assertIn("рекомендуется не более", html)


if __name__ == "__main__":
    unittest.main()
