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


if __name__ == "__main__":
    unittest.main()
