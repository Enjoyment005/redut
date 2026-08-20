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
        # оверлей стоит слева внизу, в пустом океане (просьба владельца 20.08:
        # справа сверху он закрывал Азию); bottom — чтобы не лечь на строку .hud
        self.assertIn(".geo .intel{position:absolute;left:9px;bottom:", views._BASE_CSS)


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
        # текстовый блок, а не плитки: карточных классов быть не должно
        self.assertNotIn(".vit{", views._BASE_CSS)
        self.assertNotIn(".vbar", views._BASE_CSS)
        # формат владельца (19.08, финальный): две строки через «|» —
        # «4 vCPU/4 GB RAM/69 GB|CPU 0%|RAM 9%|Диск 1%» / «Службы ✓|Аптайм 19ч|Устр. 2 из 40 max»
        self.assertIn("' vCPU/'", html)
        self.assertIn("'|CPU '", html)
        self.assertIn("'|Аптайм '", html)
        self.assertIn("' из '+rec+' max'", html)
        self.assertIn("советуем ≤", html)   # сводка раздела «Кто подключён»

    def test_vitals_sits_under_subline_not_under_buttons(self):
        # владелец: строка ПРЯМО ПОД подстрокой шапки (внутри .brand),
        # а не после блока кнопок .tools
        html = views._DASH_HTML
        vit = html.find('id="vitals"')
        self.assertGreater(vit, html.find('id="subline"'))
        self.assertLess(vit, html.find('class="tools"'))

    def test_vitals_colors_survive_brand_gradient(self):
        # .brand красит текст градиентом (background-clip:text): без явного
        # -webkit-text-fill-color зелёный/жёлтый/красный в строке пропадут
        css = views._BASE_CSS
        for rule in (".vitals{color:var(--mut);-webkit-text-fill-color:var(--mut)",
                     ".vitals .ok{-webkit-text-fill-color:var(--green)}",
                     ".vitals .warn{-webkit-text-fill-color:var(--amber)}",
                     ".vitals .bad{-webkit-text-fill-color:var(--pink)}",
                     ".vitals .q{-webkit-text-fill-color:var(--cyan)}"):
            self.assertIn(rule, css)

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


class TestToolbarCompact(unittest.TestCase):
    """Компактный тулбар (19.08): один ряд под шапкой, подсказки на самих
    кнопках (data-h), «?»-кружков и обёрток .btnq в тулбаре нет, «Выход»
    прижат вправо. Иначе «Выход» снова сползёт на свою строку."""

    def _tools(self):
        html = views._DASH_HTML
        start = html.find('class="tools"')
        end = html.find("</form>", start)          # «Выход» — последний элемент тулбара
        self.assertGreater(start, -1)
        self.assertGreater(end, start)
        return html[start:end]

    def test_no_circles_inside_toolbar(self):
        tools = self._tools()
        self.assertNotIn("btnq", tools)
        self.assertNotIn('class="q"', tools)

    def test_buttons_carry_hints_and_groups(self):
        tools = self._tools()
        self.assertGreaterEqual(tools.count("data-h="), 8)
        self.assertIn('class="vsep"', tools)      # разделитель групп
        self.assertIn('class="grow"', tools)      # «Выход» и тумблеры — вправо
        self.assertGreaterEqual(tools.count("btn s tiny"), 4)

    def test_tip_delegation_covers_data_h_buttons(self):
        # облачко подсказки обязано реагировать не только на .q, но и на
        # любые элементы с data-h — на них теперь держится весь тулбар
        self.assertIn("'.q,[data-h]'", views._DASH_HTML)


if __name__ == "__main__":
    unittest.main()
