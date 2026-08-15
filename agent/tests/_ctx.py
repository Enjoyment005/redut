# -*- coding: utf-8 -*-
"""Общий контекст тестов: панель в sys.path + загрузка фикстур."""
import json
import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PANEL_DIR = os.path.dirname(TESTS_DIR)
if PANEL_DIR not in sys.path:
    sys.path.insert(0, PANEL_DIR)


def fixture(name):
    with open(os.path.join(TESTS_DIR, "fixtures", name), encoding="utf-8") as f:
        return json.load(f)
