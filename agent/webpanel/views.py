# -*- coding: utf-8 -*-
"""HTML-шаблоны панели (inline, без внешних ресурсов — CSP запрещает внешнее).

Тема «cyber» — тёмный HUD оператора: градиентный фон, сетка, неоновые акценты
(cyan/green/magenta/purple), уголки-скобки на карточках, моноширинные данные.
Шрифты и картинки не грузятся из сети (CSP `default-src 'none'`): вся графика —
CSS-градиенты и inline-SVG, шрифты — системные.

Второй принцип: **панель должна быть понятна новичку**. Поэтому у каждого блока
есть пояснение простым языком (класс `.ex`, тумблер «Объяснения» в шапке), а у
терминов — всплывающие подсказки (`_q(...)`). Тексты пишем без жаргона:
«прокси, через который сервер выходит в интернет», а не «upstream socks-out».
"""

_BASE_CSS = """
:root{
--bg:#04060c;--card:#0c1120;--card2:#111a2e;--line:#1a2744;--line2:#243559;
--fg:#e3ebf7;--mut:#8095bb;--dim:#4d5d80;
--cyan:#00f0ff;--green:#05ffa1;--pink:#ff2a6d;--purple:#b47aff;--amber:#ffb800;
--mono:'JetBrains Mono','Cascadia Mono',Consolas,'DejaVu Sans Mono',ui-monospace,monospace;
--ui:'Chakra Petch','Segoe UI',system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
html{min-height:100%;background:linear-gradient(160deg,#1a0a2e 0%,#0f0a1e 25%,#0a0c18 50%,#06080f 75%,#04060c 100%);background-attachment:fixed}
body{margin:0;min-height:100vh;color:var(--fg);font:14px/1.55 var(--ui)}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
background:linear-gradient(rgba(0,240,255,.016) 1px,transparent 1px),linear-gradient(90deg,rgba(0,240,255,.016) 1px,transparent 1px);
background-size:50px 50px}
body::after{content:'';position:fixed;z-index:0;pointer-events:none;width:700px;height:700px;top:-250px;left:-150px;
background:radial-gradient(circle,rgba(120,40,200,.10),transparent 70%);filter:blur(80px)}
.wrap{position:relative;z-index:1;max-width:1180px;margin:0 auto;padding:18px 16px 70px}
a{color:var(--cyan)}
::selection{background:rgba(0,240,255,.25)}

/* ── шапка ─────────────────────────────────────────────────────────── */
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap;margin-bottom:6px}
.brand{font:700 20px/1.1 var(--ui);letter-spacing:.16em;text-transform:uppercase;
background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;background-clip:text;color:transparent}
.brand small{display:block;font:400 11px/1.6 var(--mono);letter-spacing:.08em;color:var(--mut);
-webkit-text-fill-color:var(--mut);text-transform:none}
.cursor{display:inline-block;width:8px;height:14px;background:var(--cyan);vertical-align:-2px;margin-left:4px;
animation:blink 1.1s steps(2,start) infinite;box-shadow:0 0 8px var(--cyan)}
@keyframes blink{50%{opacity:0}}
.tools{display:flex;gap:7px;flex-wrap:wrap;align-items:center;justify-content:flex-end}

/* ── карточки с HUD-уголками ───────────────────────────────────────── */
.card{position:relative;background-color:var(--card);border:1px solid var(--line);border-radius:12px;
padding:15px 17px;margin:14px 0;transition:border-color .25s,box-shadow .25s;
background-image:linear-gradient(var(--cyan),var(--cyan)),linear-gradient(var(--cyan),var(--cyan)),
linear-gradient(var(--cyan),var(--cyan)),linear-gradient(var(--cyan),var(--cyan)),
linear-gradient(var(--cyan),var(--cyan)),linear-gradient(var(--cyan),var(--cyan)),
linear-gradient(var(--cyan),var(--cyan)),linear-gradient(var(--cyan),var(--cyan));
background-position:0 0,0 0,100% 0,100% 0,0 100%,0 100%,100% 100%,100% 100%;
background-size:14px 1px,1px 14px;background-repeat:no-repeat}
.card:hover{border-color:rgba(0,240,255,.28);box-shadow:0 0 0 1px rgba(0,240,255,.06),0 6px 26px rgba(0,0,0,.45)}
.card>h2{margin:0 0 3px;font:600 12px/1.2 var(--ui);letter-spacing:.16em;text-transform:uppercase;
color:var(--cyan);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.card>h2::before{content:'';width:6px;height:6px;border-radius:1px;background:var(--cyan);box-shadow:0 0 9px var(--cyan);flex:none}
.card>h2 .r{margin-left:auto;display:flex;gap:7px;align-items:center}
/* сворачиваемые карточки (П2/П4): заголовок кликабелен, тело прячется */
.card.fold>h2{cursor:pointer;user-select:none}
.card.fold>h2 .arr{color:var(--mut);font:600 12px/1 var(--mono)}
.card.folded .fold-body{display:none}
h1{font-size:18px;margin:0}
.sub{color:var(--mut);font:400 12px/1.5 var(--mono)}

/* ── пояснения «для чайника» ───────────────────────────────────────── */
.ex{border-left:2px solid rgba(0,240,255,.4);background:rgba(0,240,255,.045);color:#adc0e0;
font:400 12.5px/1.6 var(--ui);padding:8px 11px;border-radius:0 8px 8px 0;margin:9px 0 12px}
.ex b{color:#d7e6ff;font-weight:600}
.ex.warn{border-left-color:rgba(255,184,0,.55);background:rgba(255,184,0,.05);color:#e3c98d}
.ex.danger{border-left-color:rgba(255,42,109,.55);background:rgba(255,42,109,.06);color:#ffb3c8}
body.noex .ex{display:none}
/* Подсказка. Само облачко живёт в единственном #tip на body с position:fixed —
   иначе его режут контейнеры со скроллом и overflow:hidden (плитки, таблицы, шапка). */
.q{display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;
border:1px solid rgba(0,240,255,.45);background:rgba(0,240,255,.08);color:var(--cyan);border-radius:50%;
font:600 10px/1 var(--mono);cursor:help;margin-left:5px;vertical-align:1px;flex:none}
.q:hover{background:rgba(0,240,255,.2)}
.q:focus{outline:none;box-shadow:0 0 0 2px rgba(0,240,255,.25)}
.btnq{display:inline-flex;align-items:center;gap:3px}   /* кнопка и её «?» не разъезжаются */
#tip{position:fixed;z-index:200;max-width:300px;background:#08101f;border:1px solid rgba(0,240,255,.4);
border-radius:9px;padding:9px 11px;color:#cfe0f5;font:400 12px/1.55 var(--ui);text-align:left;
letter-spacing:0;text-transform:none;box-shadow:0 12px 34px rgba(0,0,0,.75);pointer-events:none;
opacity:0;visibility:hidden;transition:opacity .14s}
#tip.on{opacity:1;visibility:visible}

/* ── маяк состояния ────────────────────────────────────────────────── */
.beacon{display:flex;gap:13px;align-items:flex-start;border:1px solid var(--line);border-radius:12px;
padding:13px 15px;background:rgba(255,255,255,.02);margin:14px 0}
.beacon .dot{width:11px;height:11px;border-radius:50%;flex:none;margin-top:5px;animation:pulse 2.4s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 currentColor;opacity:1}55%{box-shadow:0 0 0 7px rgba(0,0,0,0);opacity:.55}}
.beacon .ttl{font:700 15px/1.35 var(--ui);letter-spacing:.02em}
.beacon .txt{color:#a9bcdc;font-size:13px;margin-top:2px}
.beacon.b-ok{border-color:rgba(5,255,161,.35);background:rgba(5,255,161,.055)}
.beacon.b-ok .dot,.beacon.b-ok .ttl{color:var(--green)}
.beacon.b-warn{border-color:rgba(255,184,0,.4);background:rgba(255,184,0,.055)}
.beacon.b-warn .dot,.beacon.b-warn .ttl{color:var(--amber)}
.beacon.b-bad{border-color:rgba(255,42,109,.45);background:rgba(255,42,109,.07)}
.beacon.b-bad .dot,.beacon.b-bad .ttl{color:var(--pink)}

/* ── карта выхода: HUD на canvas ────────────────────────────────────
   Тайлов и чужих библиотек тут быть не может (CSP `default-src 'none'`),
   поэтому карта рисуется целиком в браузере: точечная маска суши лежит
   в самой панели. Ширина — по блоку, высота считается из пропорций карты. */
.geo .map{position:relative;margin-top:10px;border:1px solid var(--line2);border-radius:9px;overflow:hidden;
background:radial-gradient(ellipse 60% 80% at 50% 45%,rgba(0,240,255,.07),transparent 70%),
linear-gradient(180deg,#060b16,#04060e)}
.geo canvas{display:block;width:100%;height:auto}
.geo .lock{position:absolute;left:9px;top:9px;max-width:calc(100% - 18px);padding:5px 8px;
border:1px solid var(--line2);border-radius:5px;background:rgba(4,7,15,.72);color:var(--cyan);
font:600 10px/1 var(--mono);letter-spacing:.13em;text-transform:uppercase;pointer-events:none;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.geo .hud{position:absolute;left:0;right:0;bottom:0;display:flex;gap:12px;flex-wrap:wrap;
justify-content:space-between;padding:7px 10px;color:var(--mut);font:400 10.5px/1.4 var(--mono);
pointer-events:none;background:linear-gradient(180deg,transparent,rgba(4,6,12,.82) 65%)}
@media(max-width:640px){.geo .hud{font-size:9.5px}.geo .lock{font-size:9px;letter-spacing:.06em}}
@media(prefers-reduced-motion:reduce){.beacon .dot{animation:none}}

/* ── плитки метрик ─────────────────────────────────────────────────── */
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:11px}
.tile{position:relative;background:var(--card2);border:1px solid var(--line);border-radius:10px;padding:10px 12px;overflow:hidden}
.tile::after{content:'';position:absolute;left:0;right:0;bottom:0;height:2px;
background:linear-gradient(90deg,transparent,var(--cyan),transparent);opacity:.75}
.tile:nth-child(4n+2)::after{background:linear-gradient(90deg,transparent,var(--green),transparent)}
.tile:nth-child(4n+3)::after{background:linear-gradient(90deg,transparent,var(--pink),transparent)}
.tile:nth-child(4n+4)::after{background:linear-gradient(90deg,transparent,var(--purple),transparent)}
.tile .k{color:var(--mut);font:500 10px/1.4 var(--mono);letter-spacing:.12em;text-transform:uppercase;
display:flex;align-items:center}
.tile .v{font:600 15px/1.35 var(--mono);margin-top:3px;word-break:break-word}

/* ── таблицы ───────────────────────────────────────────────────────── */
.scroll{overflow:auto;margin:0 -3px;padding:0 3px}
table{width:100%;border-collapse:collapse;font:400 12.5px/1.5 var(--mono)}
th,td{text-align:left;padding:8px 9px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mut);font:500 10px/1.4 var(--mono);letter-spacing:.11em;text-transform:uppercase}
tbody tr:hover td{background:rgba(0,240,255,.04)}
tr.cur td{background:rgba(5,255,161,.07)}
tr.cur td:first-child{box-shadow:inset 2px 0 0 var(--green)}

/* ── кнопки/поля ───────────────────────────────────────────────────── */
.btn{font:600 12px/1 var(--ui);letter-spacing:.03em;background:rgba(0,240,255,.12);
border:1px solid rgba(0,240,255,.45);color:var(--cyan);padding:8px 12px;border-radius:7px;cursor:pointer;transition:.18s}
.btn:hover{background:rgba(0,240,255,.22);box-shadow:0 0 15px rgba(0,240,255,.3)}
.btn:disabled{opacity:.35;cursor:default;box-shadow:none}
.btn.g{background:rgba(5,255,161,.12);border-color:rgba(5,255,161,.45);color:var(--green)}
.btn.g:hover{background:rgba(5,255,161,.22);box-shadow:0 0 15px rgba(5,255,161,.3)}
.btn.r{background:rgba(255,42,109,.12);border-color:rgba(255,42,109,.45);color:var(--pink)}
.btn.r:hover{background:rgba(255,42,109,.22);box-shadow:0 0 15px rgba(255,42,109,.3)}
.btn.a{background:rgba(255,184,0,.12);border-color:rgba(255,184,0,.45);color:var(--amber)}
.btn.a:hover{background:rgba(255,184,0,.22);box-shadow:0 0 15px rgba(255,184,0,.3)}
.btn.s{background:rgba(255,255,255,.05);border-color:var(--line2);color:#b8c7e4}
.btn.s:hover{background:rgba(255,255,255,.09);box-shadow:none}
.btn.tiny{padding:5px 9px;font-size:11px}
input,select{background:#070c17;color:var(--fg);border:1px solid var(--line2);border-radius:7px;
padding:9px 10px;width:100%;font:400 13px/1.3 var(--mono);transition:.15s}
input:focus,select:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 2px rgba(0,240,255,.18)}
input::placeholder{color:var(--dim)}
label{display:block;margin:11px 0 5px;color:var(--mut);font:500 10px/1.4 var(--mono);letter-spacing:.11em;text-transform:uppercase}
.field{display:flex;gap:9px;align-items:flex-end;flex-wrap:wrap}
.field label{margin-top:0}

/* ── мелочи ────────────────────────────────────────────────────────── */
.pill{display:inline-block;padding:2px 8px;border-radius:20px;font:500 11px/1.5 var(--mono);border:1px solid var(--line2);color:var(--mut)}
.pill.ok{border-color:rgba(5,255,161,.45);color:var(--green);background:rgba(5,255,161,.08)}
.pill.bad{border-color:rgba(255,42,109,.45);color:var(--pink);background:rgba(255,42,109,.08)}
.pill.warn{border-color:rgba(255,184,0,.45);color:var(--amber);background:rgba(255,184,0,.08)}
.ok{color:var(--green)}.bad{color:var(--pink)}.warn{color:var(--amber)}.mut{color:var(--mut)}
.mono{font-family:var(--mono)}

/* ── прогресс обновления (карточка «Обновления», 1.6.0) ─────────────── */
.pwrap{margin:10px 0 4px}
.pbar{position:relative;height:16px;border:1px solid var(--line2);border-radius:9px;overflow:hidden;
background:rgba(4,8,16,.85);box-shadow:inset 0 1px 4px rgba(0,0,0,.5)}
.pfill{height:100%;width:0;border-radius:8px 0 0 8px;transition:width .9s ease;
background:repeating-linear-gradient(-55deg,rgba(255,255,255,.14) 0 9px,rgba(255,255,255,0) 9px 18px),
linear-gradient(90deg,rgba(0,240,255,.55),rgba(5,255,161,.75));
background-size:26px 100%,100% 100%;animation:pmove 1.1s linear infinite;
box-shadow:0 0 12px rgba(5,255,161,.35)}
.pfill.ok{animation:none;background:linear-gradient(90deg,rgba(5,255,161,.6),rgba(5,255,161,.85))}
.pfill.bad{background:repeating-linear-gradient(-55deg,rgba(255,255,255,.12) 0 9px,rgba(255,255,255,0) 9px 18px),
linear-gradient(90deg,rgba(255,42,109,.55),rgba(255,42,109,.8));box-shadow:0 0 12px rgba(255,42,109,.35)}
@keyframes pmove{to{background-position:26px 0,0 0}}
.pbar .plabel{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
font:600 10px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:#eaf6ff;
text-shadow:0 1px 3px rgba(0,0,0,.8)}
.psteps{display:flex;gap:6px;flex-wrap:wrap;margin-top:7px}
.pstep{flex:1 1 0;min-width:96px;text-align:center;padding:4px 6px;border:1px solid var(--line);
border-radius:7px;color:var(--dim);font:500 10px/1.5 var(--mono);letter-spacing:.06em;text-transform:uppercase;
background:rgba(255,255,255,.015)}
.pstep.done{color:var(--green);border-color:rgba(5,255,161,.4);background:rgba(5,255,161,.06)}
.pstep.act{color:var(--cyan);border-color:rgba(0,240,255,.5);background:rgba(0,240,255,.07);
animation:pulse 2.4s infinite}
.pstep.bad{color:var(--pink);border-color:rgba(255,42,109,.5);background:rgba(255,42,109,.07)}
@media(prefers-reduced-motion:reduce){.pfill{animation:none}.pstep.act{animation:none}}
details{border:1px solid var(--line);border-radius:10px;padding:10px 13px;background:rgba(255,255,255,.02);margin-top:12px}
details summary{cursor:pointer;color:var(--cyan);font:600 12px/1.4 var(--ui);letter-spacing:.08em;text-transform:uppercase}
details[open] summary{margin-bottom:8px}
details .ex{margin-top:8px}
.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:10px}
.step{border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:rgba(255,255,255,.02);font-size:12.5px;color:#b6c7e6}
.step b{display:block;color:var(--cyan);font:600 11px/1.5 var(--mono);letter-spacing:.1em;text-transform:uppercase;margin-bottom:3px}
#toast{position:fixed;right:16px;bottom:16px;max-width:430px;z-index:80}
.msg{background:#0a1120;border:1px solid var(--line2);border-left:3px solid var(--cyan);border-radius:9px;
padding:10px 12px;margin-top:8px;font:400 12.5px/1.55 var(--mono);white-space:pre-wrap;
box-shadow:0 10px 30px rgba(0,0,0,.6);word-break:break-word}
.msg.ok{border-left-color:var(--green)}.msg.bad{border-left-color:var(--pink)}.msg.warn{border-left-color:var(--amber)}
.center{max-width:400px;margin:7vh auto}
.flags span{display:inline-block;width:16px;text-align:center;font-weight:700}
.qrwrap{background:#fff;display:inline-block;padding:9px;border-radius:9px;box-shadow:0 0 24px rgba(0,240,255,.25)}
.foot{color:var(--dim);font:400 11px/1.6 var(--mono);text-align:center;margin-top:26px}
@media(max-width:640px){.top{flex-direction:column}.tools{justify-content:flex-start}.card{padding:13px 13px}}
"""


# ─────────────────────────── помощники ──────────────────────────────────
def _q(text):
    """Всплывающая подсказка-глоссарий: кружок «?» рядом с термином."""
    return '<i class="q" tabindex="0" data-h="%s">?</i>' % _esc(text)


def _fill(tpl, **kw):
    """Подстановка __КЛЮЧ__ вместо %-форматирования (в CSS/JS полно % и {})."""
    for k, v in kw.items():
        tpl = tpl.replace("__%s__" % k, v)
    return tpl


# ─────────────────────────── вход ───────────────────────────────────────
_LOGIN_HTML = """
<div class="center">
  <div class="brand" style="text-align:center;margin-bottom:14px">VPN&nbsp;PANEL<small>защищённый вход · пароль + одноразовый код</small></div>
  <div class="card">
    <h2>Авторизация</h2>
    __ERR____NOTE__
    <form method="POST" action="/login">
      <label>Пароль</label><input name="password" type="password" autofocus autocomplete="off">
      <label>Код из приложения (6 цифр) или recovery-код</label><input name="otp" autocomplete="off" placeholder="123456">
      <div style="margin-top:16px"><button class="btn" type="submit" style="width:100%;padding:11px">Войти →</button></div>
    </form>
    <div class="ex" style="margin-top:14px">Второй фактор — 6-значный код из приложения-аутентификатора
      (Google Authenticator, Aegis, 1Password). Код меняется каждые 30 секунд. Потерял телефон —
      введи вместо кода один из <b>recovery-кодов</b>, которые выдавались при настройке.</div>
  </div>
  <div class="foot">5 неудачных попыток подряд — временный бан IP</div>
</div>
"""


def login_page(error="", note=""):
    err = ('<div class="msg bad">%s</div>' % _esc(error)) if error else ""
    nt = ('<div class="msg">%s</div>' % _esc(note)) if note else ""
    return _doc("Вход — vpn-panel", _fill(_LOGIN_HTML, ERR=err, NOTE=nt))


# ─────────────────────────── данные карты выхода ────────────────────────
# Суша — битовая маска 240×84 ячейки (шаг 1.5°, широты −51…75°, вся долгота),
# страны — их label-точки. Источник: Natural Earth 110m admin_0 (public domain),
# пересчитано скриптом при разработке. Держим прямо в панели, потому что CSP
# узла запрещает внешние ресурсы (`default-src 'none'`), да и незачем узлу
# ходить в интернет за картинкой. Точность тут не нужна: панель показывает
# СТРАНУ выхода — geoip и сам не знает большего.
_MAP_COLS, _MAP_ROWS = 240, 84
_MAP_BOX = (-180.0, 180.0, -51.0, 75.0)     # lon0, lon1, lat0, lat1

_MAP_LAND = (
    "AAAAAAcAAAAAAD///8AAAAAAAAYAAD//gAAAAAAAAAAAAAe6zs/AAB///4AAAAAAABgDA/////wGAAAAwAEAAAI/wM//AAf/"
    "/4AAAAAAABwHf/////z/+AABAB//wPI/+sEP4A///wAAAAf8AACHf////////8B8wH/////ww3mB4Af/8AAAAD//xjf7v///"
    "////////7A////////+B/g//gAAAAH//4///f///////////GH////////0P5Af4AH4AAPx+H///////////////AAf/////"
    "//Ng+AP4ADAAA/n////////////////+AD///////8COMAHwAAAAD/P///////////////v8AD/7/////4APwABgAAAAH/P/"
    "/////////////wfAAA+AH////4APzAAAAAAAD/D/////////////JhgAAAFAAf///8AH/gAAAAAIAOD////////////4AHAA"
    "AAQAAP////wH/gAAAAAMBuP////////////wAPgAACAAAH////+f/8AAAAAWAhf////////////AAPAAAAAAAT////+f/+AA"
    "AAA3H//////////////+AOAAAAAAAB/////f/8AAAAAHn//////////////+AIAAAAAAAB//////8wAAAAAMf///////////"
    "///9AAAAAAAAAA//////2HAAAAAF///////////////4AAAAAAAAAAf/////+AgAAAAD///////////////4AAAAAAAAAAf/"
    "/////wAAAAAB///yfx/////////wAAAAAAAAAAf/////yAAAAAAB/z/gPj/////////jAAAAAAAAAAf/////gAAAAAA/wY/g"
    "Dx////////8HAAAAAAAAAAf/////AAAAAAA/gGfnn4////////wAAAAAAAAAAAf////+AAAAAAA/ACY//4///////1gGAAAA"
    "AAAAAAP////8AAAAAAA/ACM//4///////hwEAAAAAAAAAAH////4AAAAAAAOLgA//////////4wcAAAAAAAAAAH////4AAAA"
    "AAAN/gDC/////////wz8AAAAAAAAAAB////wAAAAAAAf/gAA/////////wDgAAAAAAAAAAA////AAAAAAAA//8YB////////"
    "/4EAAAAAAAAAAAAH///AAAAAAAA///f//////////4AAAAAAAAAAAAAX/5BAAAAAAAB//////z///////4AAAAAAAAAAAAAb"
    "/gBAAAAAAAH////8/5///////4AAAAAAAAAAAAAF/gBoAAAAAAP////+/4f//////wAAAAAAAAAAAAAE/gAAAAAAAAP////+"
    "f8wH/////gAAAAAAAAAAAAAAfgAAAAAAAAf/////P/4D/////IAAAAAAAAAAAAAAPgAQAAAAAAf/////v/8D/+f/4AAAAAAA"
    "AAAAAAAAPgwOAAAAAAf/////n/4Af8P+AAAAAAAAAAAAAAAAHxwAwAAAAAf/////n/wAfwH+wAAAAAAAAAAAAAAAB/gAAAAA"
    "AAf/////z/gAfgH+AMAAAAAAAAAAAAAAAT8AAAAAAAf/////z+AAfAF/AIAAAAAAAAAAAAAAAB+AAAAAAAf/////94AAOAB/"
    "gIAAAAAAAAAAAAAAAAMAAAAAAAf//////AAAOAA/gCAAAAAAAAAAAAAAAAEBQAAAAAP/////+MAAGAAHAFAAAAAAAAAAAAAA"
    "AACDfgAAAAH//////8AAGAACAAAAAAAAAAAAAAAAAABP/wAAAAH//////4AABABgADAAAAAAAAAAAAAAAAAP/4AAAAD/////"
    "/4AABAAQABAAAAAAAAAAAAAAAAAP//gAAAA/H////wAAAACYBgAAAAAAAAAAAAAAAAAH//wAAAAAA////wAAAADYDAAAAAAA"
    "AAAAAAAAAAAP//wAAAAAA////gAAAABoPgAAAAAAAAAAAAAAAAAf//4AAAAAA///+AAAAAA4fuQAAAAAAAAAAAAAAAA///+A"
    "AAAAA///8AAAAAAYfASAAAAAAAAAAAAAAAA////AAAAAA///4AAAAAAcfYBYAAAAAAAAAAAAAAA////8AAAAAf//4AAAAAAO"
    "CEh/AAAAAAAAAAAAAAA/////AAAAAP//wAAAAAAGAAAPgAAAAAAAAAAAAAA/////gAAAAP//wAAAAAADIABPwIAAAAAAAAAA"
    "AAAf////gAAAAH//wAAAAAAAOAAPYCAAAAAAAAAAAAAP////AAAAAH//4AAAAAAAACAAMAAAAAAAAAAAAAAP///+AAAAAH//"
    "4AAAAAAAAAAAAAAAAAAAAAAAAAAH///+AAAAAH//4AAAAAAAAAHhAAAAAAAAAAAAAAAH///8AAAAAP//4IAAAAAAAAvjAAAA"
    "AAAAAAAAAAAD///8AAAAAP//4cAAAAAAAB/jgAAAAAAAAAAAAAAA///8AAAAAP//h4AAAAAAAD/7gAAAAAAAAAAAAAAAf//8"
    "AAAAAP//B4AAAAAAAH//wAAAAAAAAAAAAAAAf//4AAAAAH/+AwAAAAAAAf//4AQAAAAAAAAAAAAAf//4AAAAAH//BwAAAAAA"
    "B///8AIAAAAAAAAAAAAAf//gAAAAAD//BwAAAAAAD///+AAAAAAAAAAAAAAAf/8AAAAAAD/+BgAAAAAAD////AAAAAAAAAAA"
    "AAAAf/8AAAAAAD/8AAAAAAAAD////AAAAAAAAAAAAAAAf/8AAAAAAD/8AAAAAAAAD////AAAAAAAAAAAAAAA//4AAAAAAB/4"
    "AAAAAAAAB////AAAAAAAAAAAAAAA//wAAAAAAA/wAAAAAAAAB////AAAAAAAAAAAAAAA//gAAAAAAA/gAAAAAAAAB/h//AAA"
    "AAAAAAAAAAAA//AAAAAAAA+AAAAAAAAAB+Av+AAAAAAAAAAAAAAA/8AAAAAAAAAAAAAAAAAAAAAP8AAQAAAAAAAAAAAB/8AA"
    "AAAAAAAAAAAAAAAAAAAH8AAIAAAAAAAAAAAB/4AAAAAAAAAAAAAAAAAAAAADQAAOAAAAAAAAAAAB/gAAAAAAAAAAAAAAAAAA"
    "AAAAAAAMAAAAAAAAAAAB+AAAAAAAAAAAAAAAAAAAAAAAYAAIAAAAAAAAAAAB+AAAAAAAAAAAAAAAAAAAAAAAYAAwAAAAAAAA"
    "AAAD8AAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAD4AAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAAD8AAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAD4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADwAAAAAAAAAAAAAAAAAAAAAAAAAAA")

_MAP_CC = {
    "ae": [54.5, 23.5], "af": [66.5, 34.2], "al": [20.1, 40.7], "am": [44.8, 40.5], "ao": [18.0,
    -12.2], "ar": [-64.2, -33.5], "at": [14.1, 47.5], "au": [134.0, -24.1], "az": [47.2, 40.4],
    "ba": [18.1, 44.1], "bd": [89.7, 24.2], "be": [4.8, 50.8], "bf": [-1.4, 12.7], "bg": [25.2,
    42.5], "bh": [50.55, 26.1], "bi": [29.9, -3.3], "bj": [2.4, 10.3], "bn": [114.6, 4.4], "bo":
    [-64.6, -16.7], "br": [-49.6, -12.1], "bs": [-77.1, 26.4], "bt": [90.0, 27.5], "bw": [24.2,
    -22.1], "by": [28.4, 53.8], "bz": [-88.7, 17.2], "ca": [-101.9, 60.3], "cd": [23.5, -1.9],
    "cf": [20.9, 7.0], "cg": [15.9, 0.1], "ch": [7.5, 46.7], "ci": [-5.6, 7.5], "cl": [-72.3,
    -38.2], "cm": [12.5, 4.6], "cn": [106.3, 32.5], "co": [-73.2, 3.4], "cr": [-84.1, 10.1],
    "cu": [-78.0, 21.3], "cy": [33.1, 34.9], "cz": [15.4, 49.9], "de": [9.7, 51.0], "dj": [42.5,
    12.0], "dk": [9.0, 56.0], "do": [-70.7, 19.1], "dz": [2.8, 27.4], "ec": [-78.2, -1.3], "ee":
    [25.9, 58.7], "eg": [29.4, 26.2], "eh": [-12.6, 24.0], "er": [38.3, 15.8], "es": [-3.5,
    40.1], "et": [39.1, 8.0], "fi": [27.3, 63.3], "fj": [178.0, -17.8], "fk": [-58.7, -51.6],
    "fr": [2.6, 46.7], "ga": [11.8, -0.4], "gb": [-2.1, 54.4], "ge": [43.7, 41.9], "gh": [-1.0,
    7.7], "gi": [-5.35, 36.14], "gl": [-39.3, 74.3], "gm": [-15.0, 13.6], "gn": [-10.0, 10.6],
    "gq": [9.0, 2.3], "gr": [21.7, 39.5], "gt": [-90.5, 15.0], "gw": [-14.5, 12.2], "gy":
    [-58.9, 5.1], "hk": [114.2, 22.3], "hn": [-86.9, 14.8], "hr": [16.4, 45.8], "ht": [-72.2,
    19.3], "hu": [19.4, 47.1], "id": [101.9, -1.0], "ie": [-7.8, 53.1], "il": [34.8, 30.9],
    "in": [79.4, 22.7], "iq": [43.3, 33.1], "ir": [54.9, 32.2], "is": [-18.7, 64.8], "it":
    [11.1, 44.7], "jm": [-77.3, 18.1], "jo": [36.4, 30.8], "jp": [138.4, 36.1], "ke": [37.9,
    0.5], "kg": [74.5, 41.7], "kh": [104.5, 12.6], "kp": [126.4, 39.9], "kr": [128.1, 36.4],
    "kw": [47.3, 29.4], "kz": [68.7, 49.1], "la": [102.5, 19.4], "lb": [36.0, 34.1], "li":
    [9.55, 47.15], "lk": [80.7, 7.6], "lr": [-9.5, 6.4], "ls": [28.2, -29.5], "lt": [24.1,
    55.1], "lu": [6.1, 49.7], "lv": [25.5, 57.1], "ly": [18.0, 26.6], "ma": [-7.2, 31.7], "mc":
    [7.4, 43.7], "md": [28.5, 47.4], "me": [19.1, 42.8], "mg": [46.7, -18.6], "mk": [21.6,
    41.6], "ml": [-2.0, 18.7], "mm": [95.8, 21.6], "mn": [104.2, 46.0], "mo": [113.5, 22.2],
    "mr": [-9.7, 19.6], "mt": [14.4, 35.9], "mu": [57.55, -20.3], "mv": [73.5, 4.2], "mw":
    [33.6, -13.4], "mx": [-102.3, 23.9], "my": [113.8, 2.5], "mz": [37.8, -13.9], "na": [17.1,
    -20.6], "nc": [165.1, -21.1], "ne": [9.5, 17.4], "ng": [7.5, 9.4], "ni": [-85.1, 12.7],
    "nl": [5.6, 52.4], "no": [9.7, 61.4], "np": [83.6, 28.3], "nz": [172.8, -39.8], "om": [57.3,
    22.1], "pa": [-80.4, 8.7], "pe": [-72.9, -13.0], "pg": [143.9, -5.7], "ph": [122.5, 11.2],
    "pk": [68.5, 29.3], "pl": [19.5, 52.0], "pr": [-66.5, 18.2], "ps": [35.3, 32.0], "pt":
    [-8.3, 39.6], "py": [-60.1, -21.7], "qa": [51.1, 25.2], "ro": [25.0, 45.7], "rs": [20.8,
    44.2], "ru": [44.7, 58.2], "rw": [30.1, -1.9], "sa": [44.7, 23.8], "sb": [159.2, -8.0],
    "sc": [55.5, -4.6], "sd": [29.3, 16.3], "se": [19.0, 65.9], "sg": [103.8, 1.35], "si":
    [14.9, 46.1], "sk": [19.0, 48.7], "sl": [-11.8, 8.6], "sm": [12.45, 43.94], "sn": [-14.8,
    15.1], "so": [45.2, 3.6], "sr": [-55.9, 4.1], "ss": [30.4, 7.2], "sv": [-88.9, 13.7], "sy":
    [38.3, 35.0], "sz": [31.5, -26.5], "td": [18.6, 15.1], "tf": [69.1, -49.3], "tg": [1.1,
    8.8], "th": [101.1, 15.5], "tj": [72.6, 38.2], "tl": [125.9, -8.8], "tm": [58.7, 39.9],
    "tn": [9.0, 33.7], "tr": [34.5, 39.3], "tt": [-60.9, 11.0], "tw": [120.9, 23.7], "tz":
    [35.0, -6.1], "ua": [32.1, 49.7], "ug": [32.9, 2.0], "us": [-97.5, 39.5], "uy": [-56.0,
    -33.0], "uz": [64.0, 41.7], "ve": [-64.6, 7.2], "vn": [105.4, 21.7], "vu": [166.9, -15.4],
    "xk": [20.9, 42.6], "ye": [45.9, 15.3], "za": [23.7, -29.7], "zm": [26.4, -14.7], "zw":
    [29.9, -18.9]}


# ─────────────────────────── дашборд ────────────────────────────────────
_DASH_HTML = """
<div class="wrap">
  <div class="top">
    <div class="brand">VPN&nbsp;PANEL · <span id="srv">__SRV__</span>
      <small><span id="subline">соединяюсь с сервером…</span><span class="cursor"></span></small></div>
    <div class="tools">
      <button class="btn s tiny" id="exbtn" onclick="toggleEx()" title="Показать/скрыть подсказки простым языком">💡 Объяснения: вкл</button>
      <button class="btn s tiny" id="foldbtn" onclick="foldToggleAll()" title="Развернуть или свернуть сразу все разделы">▾ Развернуть всё</button>
      <span class="btnq"><button class="btn s" onclick="egress()">Проверить выход</button><i class="q" tabindex="0"
        data-h="Безопасно, ничего не меняет. Сервер спрашивает у внешнего сайта: «какой у меня IP?» — и показывает ответ. Так видно, доходит ли трафик до зарубежного прокси.">?</i></span>
      <span class="btnq"><button class="btn s" onclick="refresh()">Обновить пул</button><i class="q" tabindex="0"
        data-h="Безопасно, денег не тратит. Заново спрашивает у провайдера список твоих прокси: какие живы, сколько дней осталось, какой баланс.">?</i></span>
      <span class="btnq"><button class="btn a" onclick="doRotate()">Ротация</button><i class="q" tabindex="0"
        data-h="Автоматическая починка. Панель проверяет текущий прокси и, если он мёртв, по порядку: подстраивает настройки → переключается на живой из пула → докупает новый (в рамках лимитов) → как крайняя мера включает аварийный режим. Может сменить прокси и потратить деньги. Если всё и так работает — ничего не делает.">?</i></span>
      <span class="btnq"><button class="btn r" id="embtn" onclick="doEmergency()">Аварийный режим</button><i class="q" tabindex="0"
        data-h="Спасательный круг, когда прокси мёртв. Трафик клиентов идёт напрямую через сервер: интернет появляется, но выход — с российского IP, то есть блокировки НЕ обходятся. Включённая вручную авария держится, пока сам её не снимешь — автоматика её не отменит. Нажми ещё раз, чтобы вернуть трафик на прокси.">?</i></span>
      <span class="btnq"><button class="btn s" id="frbtn" onclick="doFreeze()">⏸ Пауза автоматики</button><i class="q" tabindex="0"
        data-h="Пока пауза включена, сторож ничего не меняет сам: не переключает прокси, не покупает, не включает аварию. Полезно на время ручных работ. Не забудь снять — на паузе узел сам не чинится.">?</i></span>
      <span class="btnq"><button class="btn r" onclick="rollback()">Откат</button><i class="q" tabindex="0"
        data-h="Машина времени на один шаг: возвращает предыдущий рабочий конфиг из резервных копий. Нужен, если после смены прокси стало хуже, а автоматический откат не сработал.">?</i></span>
      <form method="POST" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="__CSRF__">
        <button class="btn s" type="submit">Выход</button></form>
    </div>
  </div>

  <div class="ex">Это пульт управления VPN-сервером. Здесь ты <b>выдаёшь доступ людям</b> (раздел «Кто
    подключён»), смотришь, <b>через какой зарубежный прокси</b> сервер выпускает трафик наружу, и меняешь
    его, если он умер. Кнопки, которые тратят деньги или рвут связь, подписаны отдельно.
    Не понимаешь слово — наведи на кружок <i class="q" tabindex="0" data-h="Вот такие подсказки объясняют термины. Наведи мышкой или нажми пальцем.">?</i></div>

  <div id="beacon" class="beacon"><div class="dot"></div>
    <div><div class="ttl">Проверяю состояние…</div><div class="txt">Читаю данные с сервера.</div></div></div>

  <div class="card fold geo" id="card_geo">
    <h2 onclick="foldClick(event,'geo')">Карта выхода<span class="sub" id="sum_geo"></span><span class="r"><span class="arr" id="fa_geo">▾</span></span></h2>
    <div class="fold-body">
    <div class="ex">Где в мире сайты видят твой трафик. <b>Прицел</b> — страна прокси, через который
      сервер выходит наружу; <b>пустые квадратики</b> — запасные прокси из пула, куда панель может
      переключиться, а пунктир между ними — эти самые запасные пути. Карта нарисована прямо в панели
      по встроенным данным: наружу она ничего не запрашивает и точку ставит <b>по стране</b>, а не по
      адресу — точнее geoip всё равно не знает.</div>
    <div class="map">
      <canvas id="geocv" width="1200" height="420"></canvas>
      <div class="lock" id="geolock">СВЯЗЬ ЕЩЁ НЕ ПРОВЕРЕНА</div>
      <div class="hud"><span id="geoxy">LAT — · LON —</span><span id="geowho"></span></div>
    </div>
    </div>
  </div>

  <div class="card fold folded" id="card_status">
    <h2 onclick="foldClick(event,'status')">Состояние узла<span class="sub" id="sum_status"></span><span class="r"><span class="sub" id="ts"></span><span class="arr" id="fa_status">▸</span></span></h2>
    <div class="fold-body">
    <div class="ex">Цепочка такая: <b>телефон/ноутбук → твой сервер → зарубежный прокси → интернет</b>.
      Сайты видят IP последнего звена. Если «IP на выходе» совпадает с «прокси на выходе» — цепочка цела.</div>
    <div class="grid" id="status"></div>
    </div>
  </div>

  <div class="card fold folded" id="card_money">
    <h2 onclick="foldClick(event,'money')">Деньги<span class="sub" id="sum_money"></span><span class="r"><button class="btn s tiny" onclick="market()">Что есть в продаже</button><span class="arr" id="fa_money">▸</span></span></h2>
    <div class="fold-body">
    <div class="ex">Панель умеет сама покупать прокси, когда старый умирает. Чтобы она не потратила лишнего,
      стоят лимиты (сколько покупок в день, потолок цены, неснижаемый остаток). Лимиты меняются только
      на сервере в файле <span class="mono">/etc/vpn-panel/config.json</span> — из браузера их не поправить,
      это защита от случайного клика.<br>
      <b>Где покупать:</b> Россия, Украина и Беларусь — <b>никогда</b> (жёсткий запрет в коде).
      Остальные страны разрешены, но панель ранжирует их по оценке и сама берёт только надёжные;
      рискованную страну можно купить вручную, вписав её код в поле ниже — тогда решение на тебе.<br>
      <b>Про адрес:</b> боевой прокси панель <b>продлевает сама</b>, пока он здоров — чтобы твой IP
      не менялся. Это важнее экономии: цена продления и покупки одинаковая (4 ₽/сутки), но новый адрес
      «холодный» — сайты начнут просить перелогины, капчи и подтверждения оплаты. Менять IP имеет смысл,
      только когда старый действительно умер.</div>
    <div class="grid" id="money"></div>
    <div id="marketbox" class="sub" style="margin-top:9px"></div>
    <div id="stabbox" class="sub" style="margin-top:6px"></div>
    <div class="field" style="margin-top:12px">
      <div><label>страна <i class="q" tabindex="0" data-h="Список — страны из белого списка; «есть в продаже» появляется после кнопки «Что есть в продаже». Первый пункт — панель выберет сама. «Другая страна…» открывает свободный ввод кода (fi, de, nl…) — решение на тебе, сервер всё равно не пропустит запрещённые.">?</i></label>
        <select id="buycc" style="width:220px" onchange="buyccChange(this)"><option value="">— панель выберет сама —</option></select></div>
      <div id="buyccfreebox" style="display:none"><label>код страны</label>
        <input id="buyccfree" style="width:100px" placeholder="fi" autocomplete="off"></div>
      <div><label>на сколько дней</label><input id="buyperiod" style="width:110px" placeholder="7" autocomplete="off"></div>
      <button class="btn g" onclick="buy()">Купить прокси</button>
      <span class="pill warn">спишутся реальные деньги</span>
    </div>
    </div>
  </div>

  <div class="card fold folded" id="card_pool">
    <h2 onclick="foldClick(event,'pool')">Пул прокси<span class="sub" id="sum_pool"></span><span class="r"><span class="arr" id="fa_pool">▸</span></span></h2>
    <div class="fold-body">
    <div class="ex">Список прокси, купленных у провайдера. <b>«Применить»</b> ставит выбранный прокси боевым:
      панель сначала проверит его, потом переключит сервер, проверит выход ещё раз и <b>сама откатится</b>,
      если стало хуже. Зелёная строка — тот, что работает прямо сейчас.<br>
      Под страной — <b>оценка</b>: ✅ надёжная (Европа, США — минимум лишних проверок), 🟢 нормальная,
      ⚪ нейтральная, ⚠️ рискованная (банки и платёжки часто просят подтверждения),
      ❓ спорная (базы геолокации не сошлись — для сайтов «страна скачет»).
      Подпись живёт по выбранной стратегии: при «Скорость и отклик» страна на оценку не влияет —
      панель так и пишет («не влияет»). Оценка — внутренняя, списков «избранных» больше нет:
      вручную можно купить любую страну, кроме запрещённых.
      <b>Россия, Украина и Беларусь запрещены навсегда</b> — такие прокси не покупаются и не используются.
      Страны с плохой оценкой автоматика сама не покупает, но ты можешь выбрать любую вручную.</div>
    <div class="scroll"><table id="pool"><thead><tr>
      <th>прокси</th><th>страна<i class="q" tabindex="0" data-h="Фактическая страна выхода по geoip и её оценка. Если провайдер продал прокси как одну страну, а выход из другой — панель покажет обе.">?</i></th>
      <th>адрес</th>
      <th>качество<i class="q" tabindex="0" data-h="Число — оценка с учётом ТЕКУЩЕЙ стратегии (больше = лучше; замеры последней проверки + вес страны по стратегии). Сменишь стратегию — числа и порядок пересчитаются сразу, без новой проверки. Три галочки — работает ли обычный интернет, http-канал и Telegram.">?</i></th>
      <th>срок</th>
      <th>роль<i class="q" tabindex="0" data-h="auto — панель распоряжается сама (ротация, продление, резерв); off — автоматика не трогает: не ставит боевым и не удаляет. Человек может отправить off «В бой» вручную — после успеха роль сама станет auto.">?</i></th>
      <th></th></tr></thead><tbody></tbody></table></div>
    <div class="sub" id="poolhidden" style="margin-top:8px"></div>
    <div class="ex" style="margin-top:10px"><b>Тест</b> — проверить, безопасно. <b>В бой</b> — сделать боевым
      (проверка → переключение → проверка → автооткат). <b>Продлить</b> и <b>Удалить</b> — деньги;
      удаление проходит проверки на сервере, боевой прокси удалить нельзя.</div>
    </div>
  </div>

  <div class="card fold folded" id="card_clients">
    <h2 onclick="foldClick(event,'clients')">Кто подключён<span class="sub" id="sum_clients"></span><span class="r">
      <input id="cname" style="width:180px" placeholder="имя, например phone-mine" autocomplete="off">
      <button class="btn g" onclick="addClient()">Выдать доступ</button><span class="arr" id="fa_clients">▸</span></span></h2>
    <div class="fold-body">
    <div class="ex">Каждому устройству — свой профиль. Нажми «Выдать доступ» → появится строка → <b>«Скачать»</b>
      даёт файл для компьютера, <b>«QR»</b> — картинку для телефона. На устройстве нужно приложение
      <b>WireGuard</b> (бесплатное, есть в App Store и Google Play): в нём «+» → «Сканировать QR-код»
      или «Импорт из файла».</div>
    <div id="qstart" class="steps" style="display:none">
      <div class="step"><b>шаг 1</b>Придумай имя устройства (латиницей, например <span class="mono">phone-mine</span>) и нажми «Выдать доступ».</div>
      <div class="step"><b>шаг 2</b>Установи на устройство приложение WireGuard из магазина приложений.</div>
      <div class="step"><b>шаг 3</b>Телефон — нажми «QR» и отсканируй. Компьютер — «Скачать» и открой файл в WireGuard.</div>
    </div>
    <div class="scroll"><table id="clients"><thead><tr>
      <th>имя</th><th>внутренний IP</th><th>последняя связь</th><th>скачано / отдано</th><th></th></tr></thead><tbody></tbody></table></div>
    <div id="qrpanel" style="display:none;margin-top:12px;text-align:center">
      <div id="qrimg" class="qrwrap"></div>
      <div class="sub" id="qrname" style="margin-top:6px"></div>
      <button class="btn s tiny" style="margin-top:8px" onclick="document.getElementById('qrpanel').style.display='none'">Скрыть QR</button>
    </div>
    </div>
  </div>

  <div class="card fold folded" id="card_strategy">
    <h2 onclick="foldClick(event,'strategy')">Стратегия выбора стран<span class="r"><span class="sub" id="stnow"></span><span class="arr" id="fa_strategy">▸</span></span></h2>
    <div class="fold-body">
    <div class="ex">Прокси бывают в разных странах, и они не равноценны: из Финляндии банк пустит
      без вопросов, а из Нигерии тот же банк покажет капчу и откажет в оплате — зато нигерийский
      прокси может быть быстрее и дешевле. <b>Стратегия — это правило, как панели выбирать между
      «приличной страной» и «хорошими замерами»</b>: она решает, где автоматике разрешено покупать
      и в каком порядке перебирать прокси из пула.<br>
      <b>Россия, Украина и Беларусь запрещены при любой стратегии</b> — это запрет в коде, а не
      настройка.<br>
      Смена правила <b>не трогает текущий канал</b>: он продолжит работать, а новое правило
      сработает при следующей смене — ротации, кнопке «В бой» или покупке.</div>
    <div class="sub" id="stmeta" style="margin-bottom:4px"></div>
    <div id="strategies"></div>
    </div>
  </div>

  <div class="card fold folded" id="card_keys">
    <h2 onclick="foldClick(event,'keys')">Ключи провайдеров прокси<span class="sub" id="sum_keys"></span><span class="r">
      <button class="btn s tiny" onclick="reloadFold('keys')">Обновить</button><span class="arr" id="fa_keys">▸</span></span></h2>
    <div class="fold-body">
    <div class="ex">Зарубежные прокси панель покупает и продлевает <b>в твоём кабинете у провайдера</b>,
      и для этого ей нужен оттуда <b>API-ключ</b>. Здесь его можно вписать или заменить — например,
      если завёл другой кабинет, сменил провайдера или ключ куда-то утёк. <b>Заходить на сервер по SSH
      не нужно.</b><br>
      <b>Где взять:</b> личный кабинет провайдера → раздел «API» → скопировать ключ. Панель проверит его
      сразу и покажет твой баланс, если ключ рабочий.<br>
      <b>Обратно ключ не показывается</b> — только несколько первых и последних символов, чтобы отличить
      один от другого. Хранится он на сервере в файле <span class="mono">/etc/vpn-panel/secrets.json</span>,
      закрытом от всех, кроме root.</div>
    <div id="keys"></div>
    <div class="ex warn" style="margin-top:11px">Новый ключ начинает работать сразу — <b>и для автоматики
      тоже</b>: следующая покупка или продление пойдут уже через новый кабинет. Прокси старого кабинета
      панель перестанет видеть, поэтому после смены ключа она сама заново спросит список прокси
      (это занимает до минуты).</div>
    </div>
  </div>

  <div class="card fold folded" id="card_upd">
    <h2 onclick="foldClick(event,'upd')">Обновления<span class="sub" id="sum_upd"></span><span class="r">
      <button class="btn s tiny" onclick="checkUpd(this)">Проверить сейчас</button><span class="arr" id="fa_upd">▸</span></span></h2>
    <div class="fold-body">
    <div class="ex">«Редут» умеет обновлять сам себя: раз в сутки узел сверяет свою версию с последним
      выпуском в официальном репозитории на GitHub и, если вышла новая, ночью скачивает её и
      переустанавливается своим же установщиком. <b>Обновление ничего не теряет</b>: доступы устройств,
      пароль панели, ключи провайдеров и рабочий прокси остаются как были — это то же самое повторное
      выполнение команды установки, только автоматом. Если после обновления узел сам себе не понравится
      (панель не встала, связь пропала) — он <b>откатится на прежнюю версию</b> и напишет письмо.
      Когда стоит последняя версия, доступна <b>принудительная переустановка</b> — тот же выпуск ставится
      заново: лечит узел, если файлы или службы разъехались. Ход установки виден здесь по шагам.</div>
    <div class="grid" id="upd"></div>
    <div id="updbox" class="sub" style="margin-top:9px"></div>
    <div id="updact" style="margin-top:11px"></div>
    </div>
  </div>

  <div class="card fold folded" id="card_events">
    <h2 onclick="foldClick(event,'events')">Журнал событий<span class="r"><span class="arr" id="fa_events">▸</span></span></h2>
    <div class="fold-body">
    <div class="ex">Кто и что делал: смена прокси, покупки, выдача доступов, срабатывания автоматики.
      Строка <span class="mono">actor=agent</span> — действовала автоматика, <span class="mono">actor=web</span> — человек из панели.</div>
    <div class="scroll"><table id="events"><thead><tr>
      <th>время</th><th>кто</th><th>действие</th><th>итог</th><th>подробности</th></tr></thead><tbody></tbody></table></div>
    </div>
  </div>

  <details>
    <summary>Справка: что делает каждая кнопка</summary>
    <div class="ex"><b>Проверить выход</b> — спрашивает у внешнего сайта, какой IP видно с сервера.
      Ничего не меняет, денег не тратит. С этого начинай любую диагностику.<br><br>
      <b>Обновить пул</b> — заново тянет у провайдера список твоих прокси: живы ли, сколько дней осталось,
      какой баланс. Тоже безопасно.<br><br>
      <b>Ротация</b> — автоматическая починка. Панель смотрит, работает ли выход, и по порядку пробует:
      подстроить настройки → переключиться на живой прокси из пула → докупить новый (в рамках дневных
      лимитов) → в самом крайнем случае включить аварийный режим. <b>Может сменить прокси и потратить
      деньги.</b> Если всё в порядке — просто ничего не делает.<br><br>
      <b>Аварийный режим</b> — спасательный круг. Пускает трафик клиентов напрямую через сервер:
      интернет у людей появляется сразу, но выход идёт <b>с российского IP</b>, то есть без обхода
      блокировок. Нужен, чтобы связь не молчала, пока чинится прокси. Повторное нажатие возвращает
      трафик на зарубежный прокси.<br><br>
      <b>Откат</b> — машина времени на один шаг: возвращает предыдущий рабочий конфиг из резервной копии.
      Пригодится, если после смены прокси стало хуже, а автооткат не сработал.<br><br>
      <b>Применить</b> (в таблице прокси) — сделать выбранный прокси боевым. Панель сначала проверит его,
      потом переключит сервер, потом проверит ещё раз — и вернёт старый, если стало хуже.<br><br>
      <b>Выдать доступ / Отозвать</b> (в разделе «Кто подключён») — создать профиль для устройства или
      мгновенно лишить его VPN.</div>
  </details>

  <details>
    <summary>Что делать, если интернет у клиентов пропал</summary>
    <div class="ex"><b>1.</b> Нажми «Проверить выход». Если IP на выходе не показался — умер прокси.<br>
      <b>2.</b> Нажми «Ротация» — панель сама продиагностирует и переключится на живой прокси
      (при необходимости докупит, если разрешено лимитами).<br>
      <b>3.</b> Не помогло — «Аварийный режим»: клиенты снова получат интернет, но <b>выход будет с
      российского IP сервера</b>, то есть без обхода блокировок. Это временная мера, чтобы связь не молчала.<br>
      <b>4.</b> Стало хуже после смены прокси — «Откат» вернёт предыдущий рабочий конфиг.</div>
  </details>

  <div class="foot">vpn-panel · соединение защищено самоподписанным сертификатом · данные обновляются автоматически</div>
</div>
<div id="toast"></div>
<script>
const CSRF=__CSRFJS__;
function esc(s){return (s==null?'':''+s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function toast(t,cls){const d=document.createElement('div');d.className='msg '+(cls||'');d.textContent=t;
  document.getElementById('toast').appendChild(d);setTimeout(()=>d.remove(),9000)}
/* ── подсказки: одно облачко на всю страницу, позиционируем сами ──
   Делегирование, потому что «?» рождаются и в JS (плитки, строки пула). */
(function(){const tip=document.createElement('div');tip.id='tip';document.body.appendChild(tip);
  let cur=null;
  function show(q){const t=q.getAttribute('data-h');if(!t)return;cur=q;
    tip.textContent=t;tip.classList.add('on');place(q)}
  function place(q){const r=q.getBoundingClientRect();const b=tip.getBoundingClientRect();
    const M=8;let left=r.left+r.width/2-b.width/2;
    left=Math.max(M,Math.min(left,window.innerWidth-b.width-M));   // не вылезать вбок
    let top=r.top-b.height-10;                                      // по умолчанию сверху
    if(top<M)top=r.bottom+10;                                       // не влезло — показываем снизу
    if(top+b.height>window.innerHeight-M)top=Math.max(M,window.innerHeight-b.height-M);
    tip.style.left=left+'px';tip.style.top=top+'px'}
  function hide(){cur=null;tip.classList.remove('on')}
  document.addEventListener('mouseover',e=>{const q=e.target.closest?e.target.closest('.q'):null;
    if(q&&q!==cur)show(q);else if(!q&&cur)hide()});
  document.addEventListener('focusin',e=>{const q=e.target.closest?e.target.closest('.q'):null;if(q)show(q)});
  document.addEventListener('focusout',hide);
  document.addEventListener('click',e=>{const q=e.target.closest?e.target.closest('.q'):null;
    if(q){cur===q?hide():show(q)}});              // на телефоне подсказка открывается тапом
  window.addEventListener('scroll',()=>{cur?place(cur):0},true);
  window.addEventListener('resize',hide)})();
function toggleEx(){const off=document.body.classList.toggle('noex');
  try{localStorage.setItem('vpnpanel-ex',off?'0':'1')}catch(e){}
  document.getElementById('exbtn').textContent=off?'💡 Объяснения: выкл':'💡 Объяснения: вкл'}
(function(){try{if(localStorage.getItem('vpnpanel-ex')==='0'){document.body.classList.add('noex');
  document.getElementById('exbtn').textContent='💡 Объяснения: выкл'}}catch(e){}})();
/* ── сворачивание разделов ──────────────────────────────────────────────
   Дефолт — свёрнуто ВСЁ, кроме карты выхода: панель открывается коротким
   экраном «маяк + карта», остальное человек разворачивает сам. Что развернул,
   то и останется развёрнутым — состояние по каждому разделу отдельно лежит
   в localStorage браузера (у каждого свой набор открытых разделов).
   Свёрнутый раздел НЕ дёргает свой API (reloadAll идёт через loadFold) —
   запрос уходит при разворачивании. Помеченные always — исключение: их данные
   нужны маяку и карте наверху страницы, поэтому грузятся всегда. ── */
const FOLDS={
  geo:{def:0,load:()=>geoSync()},
  status:{def:1,always:1,load:()=>loadStatus()},
  money:{def:1,load:()=>loadMoney()},
  pool:{def:1,load:()=>loadPool()},
  clients:{def:1,always:1,load:()=>loadClients()},
  strategy:{def:1,load:()=>loadStrategy()},
  keys:{def:1,load:()=>loadKeys()},
  upd:{def:1,load:()=>loadUpd()},
  events:{def:1,load:()=>loadEvents()}};
const FOLD_ORDER=['status','money','pool','clients','strategy','keys','upd','events'];
const FOLD_MEM={}; /* фолбэк на сессию, когда localStorage запрещён — иначе разделы не развернуть вовсе */
function isFolded(id){try{const v=localStorage.getItem('vpnpanel-fold-'+id);
  if(v==='0')return false;if(v==='1')return true}catch(e){}
  if(id in FOLD_MEM)return FOLD_MEM[id];
  return !!FOLDS[id].def}
function foldSet(id,to){FOLD_MEM[id]=to;
  try{localStorage.setItem('vpnpanel-fold-'+id,to?'1':'0')}catch(e){}
  applyFold(id)}
function applyFold(id){const c=document.getElementById('card_'+id);
  if(c)c.classList.toggle('folded',isFolded(id));
  const a=document.getElementById('fa_'+id);if(a)a.textContent=isFolded(id)?'▸':'▾'}
/* заголовок кликабелен целиком, но кнопка и поле ввода в нём — это они сами,
   а не «свернуть»: иначе «Выдать доступ» захлопывал бы раздел вместе с ответом */
function foldClick(ev,id){const t=ev&&ev.target;
  if(t&&t.closest&&t.closest('button,input,select,a,label,.q'))return;
  toggleFold(id)}
async function toggleFold(id){foldSet(id,!isFolded(id));foldBtn();
  if(id==='geo'&&isFolded('geo'))geoStop();
  if(!isFolded(id))try{await FOLDS[id].load()}catch(e){toast(e.message,'bad')}}
async function loadFold(id){if(FOLDS[id].always||!isFolded(id))await FOLDS[id].load()}
/* кнопка в шапке раздела: свёрнутый — развернуть (это и есть загрузка), открытый — перечитать */
async function reloadFold(id){if(isFolded(id))return toggleFold(id);
  try{await FOLDS[id].load()}catch(e){toast(e.message,'bad')}}
async function openFold(id){if(isFolded(id))await toggleFold(id)}
function foldBtn(){const b=document.getElementById('foldbtn');if(!b)return;
  b.textContent=FOLD_ORDER.some(id=>!isFolded(id))?'▴ Свернуть всё':'▾ Развернуть всё'}
async function foldToggleAll(){const to=FOLD_ORDER.some(id=>!isFolded(id));
  for(const id in FOLDS)foldSet(id,to);
  foldBtn();
  if(to){geoStop();return}
  geoSync();
  for(const id of FOLD_ORDER){try{await FOLDS[id].load()}catch(e){}}}
function sum(id,txt){const e=document.getElementById('sum_'+id);if(e)e.textContent=txt||''}
(function(){for(const id in FOLDS)applyFold(id);foldBtn()})();

/* ── карта выхода ───────────────────────────────────────────────────────
   Показывает страну, из которой сайты видят твой трафик, и запасные прокси
   пула. Рисуем сами на canvas: CSP не пускает ни чужие библиотеки, ни тайлы,
   да и узлу незачем ходить в интернет ради картинки. Суша — битовая маска
   240×84 (Natural Earth 110m, шаг 1.5°), страны — её же label-точки; всё это
   лежит в самой панели (_MAP_LAND/_MAP_CC в views.py).
   Точка ставится ПО СТРАНЕ — точнее geoip и не знает, а рисовать «дом на
   карте» панель не должна. ── */
const GEO={cols:__MAPCOLS__,rows:__MAPROWS__,l0:__MAPL0__,l1:__MAPL1__,b0:__MAPB0__,b1:__MAPB1__,
  cc:__MAPCC__,land:null,W:0,H:0,dpr:0,base:null,raf:0,last:0,run:0,st:null};
const GEOFONT='ui-monospace,SFMono-Regular,Consolas,monospace';
(function(){try{const b=atob(__MAPLAND__),a=new Uint8Array(b.length);
  for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);GEO.land=a}catch(e){}})();
function geoPt(cc){return GEO.cc[(cc||'').toLowerCase()]||null}
function geoXY(lon,lat){return [(lon-GEO.l0)/(GEO.l1-GEO.l0)*GEO.W,(GEO.b1-lat)/(GEO.b1-GEO.b0)*GEO.H]}
/* размер холста — от ширины блока; свёрнутая карта имеет ширину 0 и не рисуется */
function geoFit(){const cv=document.getElementById('geocv');
  if(!cv||!GEO.land)return null;
  const w=Math.round(cv.clientWidth||0);if(w<80)return null;
  const dpr=Math.min(2,window.devicePixelRatio||1);
  if(w!==GEO.W||dpr!==GEO.dpr){GEO.W=w;GEO.H=Math.round(w*GEO.rows/GEO.cols);GEO.dpr=dpr;
    cv.width=Math.round(GEO.W*dpr);cv.height=Math.round(GEO.H*dpr);GEO.base=geoBase()}
  return cv}
/* суша и сетка меридианов — один раз на размер, дальше просто копируем картинку */
function geoBase(){const c=document.createElement('canvas');
  c.width=Math.round(GEO.W*GEO.dpr);c.height=Math.round(GEO.H*GEO.dpr);
  const g=c.getContext('2d');g.setTransform(GEO.dpr,0,0,GEO.dpr,0,0);
  g.strokeStyle='rgba(0,240,255,.05)';g.lineWidth=1;
  for(let lon=-150;lon<=150;lon+=30){const p=geoXY(lon,0);
    g.beginPath();g.moveTo(Math.round(p[0])+.5,0);g.lineTo(Math.round(p[0])+.5,GEO.H);g.stroke()}
  for(let lat=-40;lat<=60;lat+=20){const p=geoXY(0,lat);
    g.beginPath();g.moveTo(0,Math.round(p[1])+.5);g.lineTo(GEO.W,Math.round(p[1])+.5);g.stroke()}
  const eq=geoXY(0,0);g.strokeStyle='rgba(0,240,255,.11)';
  g.beginPath();g.moveTo(0,Math.round(eq[1])+.5);g.lineTo(GEO.W,Math.round(eq[1])+.5);g.stroke();
  const cw=GEO.W/GEO.cols,ch=GEO.H/GEO.rows,d=Math.max(1,Math.min(cw,ch)*.62);
  for(let pass=0;pass<2;pass++){
    g.fillStyle=pass?'rgba(0,240,255,.5)':'rgba(96,168,214,.38)';
    for(let r=0;r<GEO.rows;r++)for(let q=0;q<GEO.cols;q++){
      if(((q+r)%5===0)!==!!pass)continue;                 /* каждая пятая точка ярче — «шум» сканера */
      const i=r*GEO.cols+q;if(!(GEO.land[i>>3]>>(7-(i&7))&1))continue;
      g.fillRect(q*cw+(cw-d)/2,r*ch+(ch-d)/2,d,d)}}
  return c}
/* дуга «куда панель может переключиться»; рисуем трижды со сдвигом, чтобы путь
   через край карты (Япония — США) не тянулся поперёк всего мира */
function geoArc(g,a,b){const W=GEO.W;let bx=b[0];
  if(bx-a[0]>W/2)bx-=W;else if(a[0]-bx>W/2)bx+=W;
  const d=Math.hypot(bx-a[0],b[1]-a[1]),mx=(a[0]+bx)/2,my=(a[1]+b[1])/2-Math.min(80,d*.3);
  for(const o of [-W,0,W]){g.beginPath();g.moveTo(a[0]+o,a[1]);
    g.quadraticCurveTo(mx+o,my,bx+o,b[1]);g.stroke()}}
/* табличка у прицела: адрес и страна выхода */
function geoTag(g,p,st,c){const t1=st.ip||'адрес неизвестен',t2=st.name||'';
  g.font='600 11px '+GEOFONT;const w1=g.measureText(t1).width;
  g.font='400 10px '+GEOFONT;const w2=t2?g.measureText(t2).width:0;
  const w=Math.max(w1,w2)+14,h=t2?31:20;
  let x=p[0]+28;if(x+w>GEO.W-6)x=p[0]-28-w;x=Math.max(4,Math.min(x,GEO.W-w-4));
  let y=p[1]-h-22;if(y<4)y=Math.min(p[1]+22,GEO.H-h-24);
  g.fillStyle='rgba(4,8,18,.86)';g.fillRect(x,y,w,h);
  g.strokeStyle='rgba('+c+',.5)';g.lineWidth=1;g.strokeRect(x+.5,y+.5,w-1,h-1);
  const lx=Math.max(x,Math.min(p[0],x+w)),ly=(y>p[1]?y:y+h);   /* поводок к ближнему краю таблички */
  g.beginPath();g.moveTo(p[0],p[1]+(y>p[1]?10:-10));g.lineTo(lx,ly);g.stroke();
  g.fillStyle='rgba('+c+',.95)';g.font='600 11px '+GEOFONT;g.fillText(t1,x+7,y+14);
  if(t2){g.fillStyle='rgba(200,220,245,.72)';g.font='400 10px '+GEOFONT;g.fillText(t2,x+7,y+26)}}
function geoDraw(t){const cv=geoFit();if(!cv)return;
  const g=cv.getContext('2d');g.setTransform(GEO.dpr,0,0,GEO.dpr,0,0);
  const W=GEO.W,H=GEO.H,st=GEO.st||{},c=st.rgb||'0,240,255',T=(t||0)/1000;
  g.clearRect(0,0,W,H);
  if(GEO.base)g.drawImage(GEO.base,0,0,W,H);
  const tgt=st.pt?geoXY(st.pt[0],st.pt[1]):null;
  const res=[];
  for(const cc of (st.pool||[])){if(cc===st.cc)continue;const p=geoPt(cc);
    if(p){const q=geoXY(p[0],p[1]);q.push(cc);res.push(q)}}
  if(tgt&&res.length){g.strokeStyle='rgba('+c+',.3)';g.lineWidth=1;
    g.setLineDash([3,6]);g.lineDashOffset=-T*(st.rot?52:14);
    for(const r of res)geoArc(g,tgt,r);g.setLineDash([])}
  g.strokeStyle='rgba(0,240,255,.6)';g.fillStyle='rgba(0,240,255,.18)';g.lineWidth=1;
  for(const r of res){const x=Math.round(r[0])-2.5,y=Math.round(r[1])-2.5;
    g.fillRect(x,y,5,5);g.strokeRect(x,y,5,5)}
  if(res.length<=12){g.font='600 10px '+GEOFONT;g.fillStyle='rgba(0,240,255,.72)';
    for(const r of res){const w=g.measureText(r[2]).width;
      g.fillText(r[2],Math.min(r[0]+7,GEO.W-w-3),r[1]+3.5)}}
  if(tgt){
    const R=Math.max(54,W*.075),a=.12+.05*Math.sin(T*1.7);
    const gr=g.createRadialGradient(tgt[0],tgt[1],0,tgt[0],tgt[1],R);
    gr.addColorStop(0,'rgba('+c+','+a.toFixed(3)+')');gr.addColorStop(1,'rgba('+c+',0)');
    g.fillStyle=gr;g.fillRect(tgt[0]-R,tgt[1]-R,R*2,R*2);
    for(let i=0;i<2;i++){const ph=((T*.45)+i*.5)%1;
      g.strokeStyle='rgba('+c+','+(.45*(1-ph)).toFixed(3)+')';g.lineWidth=1.1;
      g.beginPath();g.arc(tgt[0],tgt[1],8+ph*44,0,6.283);g.stroke()}
    g.save();g.translate(tgt[0],tgt[1]);g.rotate(T*1.05%6.283);
    const lg=g.createLinearGradient(0,0,46,0);
    lg.addColorStop(0,'rgba('+c+',.6)');lg.addColorStop(1,'rgba('+c+',0)');
    g.strokeStyle=lg;g.lineWidth=1.4;g.beginPath();g.moveTo(0,0);g.lineTo(46,0);g.stroke();g.restore();
    g.strokeStyle='rgba('+c+',.9)';g.lineWidth=1.3;
    g.beginPath();g.arc(tgt[0],tgt[1],7,0,6.283);g.stroke();
    for(const d of [[1,0],[-1,0],[0,1],[0,-1]]){g.beginPath();
      g.moveTo(tgt[0]+d[0]*11,tgt[1]+d[1]*11);g.lineTo(tgt[0]+d[0]*17,tgt[1]+d[1]*17);g.stroke()}
    g.fillStyle='rgba('+c+',1)';g.beginPath();g.arc(tgt[0],tgt[1],2.1,0,6.283);g.fill();
    geoTag(g,tgt,st,c)}
  const sy=((T*.09)%1)*H;                                  /* строка сканера сверху вниз */
  g.fillStyle='rgba('+c+',.045)';g.fillRect(0,sy-16,W,16);
  g.fillStyle='rgba('+c+',.16)';g.fillRect(0,Math.round(sy),W,1)}
function geoStill(){try{return window.matchMedia('(prefers-reduced-motion: reduce)').matches}catch(e){return false}}
function geoLoop(t){if(!GEO.run){GEO.raf=0;return}
  GEO.raf=requestAnimationFrame(geoLoop);
  if(t-GEO.last<32)return;GEO.last=t;geoDraw(t)}
function geoStart(){if(isFolded('geo')||document.hidden)return geoStop();
  if(geoStill()){geoStop();geoDraw(0);return}                /* «поменьше движения» — рисуем один кадр */
  if(GEO.run)return;GEO.run=1;GEO.last=0;GEO.raf=requestAnimationFrame(geoLoop)}
function geoStop(){GEO.run=0;if(GEO.raf)cancelAnimationFrame(GEO.raf);GEO.raf=0}
/* состояние карты — из того же /api/status, что и маяк: своих запросов карта не делает */
function geoSync(s){s=s||window.__S;if(!s||!document.getElementById('geocv'))return;
  /* без проверки выхода цели нет: рисовать прошлогоднюю страну — врать человеку */
  const cc=(s.egress_cc||'').toLowerCase(),pt=s.egress_at?geoPt(cc):null;
  let rgb='0,240,255',lock='цель не захвачена';
  if(s.emergency){rgb='255,42,109';lock='авария · прямой выход без прокси'}
  else if(s.automat==='ROTATING'){rgb='255,184,0';lock='перебор пула…'}
  else if(!s.egress_at){lock='выход ещё не проверялся'}
  else if(s.egress_ok){rgb=ccWarn(s)?'255,184,0':'5,255,161';lock='цель захвачена'}
  else{rgb='255,42,109';lock='цепь разорвана'}
  if(s.egress_at&&cc&&!pt)lock+=' · страна '+cc+' не на карте';
  const pool=(s.pool_cc||[]);
  GEO.st={pt:pt,rgb:rgb,cc:cc,ip:s.egress||'',name:country(cc)||'',pool:pool,rot:s.automat==='ROTATING'};
  const L=document.getElementById('geolock');
  if(L){L.textContent=lock+((s.egress&&s.egress_at)?(' · '+s.egress):'');
    L.style.color='rgb('+rgb+')';L.style.borderColor='rgba('+rgb+',.45)'}
  const xy=document.getElementById('geoxy');
  if(xy)xy.textContent=pt?('LAT '+pt[1].toFixed(1)+' · LON '+pt[0].toFixed(1)+' · '+(country(cc)||cc.toUpperCase()))
    :'LAT — · LON —';
  const who=document.getElementById('geowho');
  const spare=pool.filter(x=>x!==cc).length;
  if(who)who.textContent=(s.egress_at?('проверено '+agoTxt(s.egress_age)):'проверки ещё не было')+
    (spare?(' · запасных на карте: '+spare):'');
  sum('geo',pt?((country(cc)||cc.toUpperCase())+(s.egress?(' · '+s.egress):'')):'');
  geoStart()}
document.addEventListener('visibilitychange',()=>{document.hidden?geoStop():geoStart()});
window.addEventListener('resize',()=>{GEO.W=0;if(!GEO.run)geoDraw(0)});
async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-CSRF-Token':CSRF},opts.headers||{});
  const r=await fetch(path,opts);const t=await r.text();let j;try{j=JSON.parse(t)}catch(e){j={error:t}}
  if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
function fl(v){return v===1?'<span class="ok">✓</span>':v===0?'<span class="bad">✕</span>':'<span class="mut">·</span>'}
function tile(k,v,hint){return '<div class="tile"><div class="k">'+k+(hint?('<i class="q" tabindex="0" data-h="'+esc(hint)+'">?</i>'):'')+
  '</div><div class="v">'+v+'</div></div>'}
const CC={fi:'Финляндия',de:'Германия',nl:'Нидерланды',se:'Швеция',ee:'Эстония',lv:'Латвия',lt:'Литва',
  pl:'Польша',cz:'Чехия',at:'Австрия',ch:'Швейцария',gb:'Британия',fr:'Франция',it:'Италия',es:'Испания',
  us:'США',ca:'Канада',ru:'Россия',cr:'Коста-Рика',tr:'Турция',ua:'Украина',ng:'Нигерия',kz:'Казахстан',
  by:'Беларусь',md:'Молдова',ge:'Грузия',am:'Армения',az:'Азербайджан',rs:'Сербия',ro:'Румыния',
  bg:'Болгария',hu:'Венгрия',sk:'Словакия',si:'Словения',hr:'Хорватия',gr:'Греция',pt:'Португалия',
  ie:'Ирландия',dk:'Дания',no:'Норвегия',is:'Исландия',be:'Бельгия',lu:'Люксембург',jp:'Япония',
  sg:'Сингапур',hk:'Гонконг',ae:'ОАЭ',il:'Израиль',in:'Индия',br:'Бразилия',au:'Австралия',
  nz:'Новая Зеландия',mx:'Мексика',cl:'Чили',ar:'Аргентина',za:'ЮАР',cn:'Китай',kr:'Корея',
  th:'Таиланд',vn:'Вьетнам',ph:'Филиппины',id:'Индонезия',my:'Малайзия'};
function country(cc){if(!cc)return '';const c=(''+cc).toLowerCase();return CC[c]||c.toUpperCase()}
/* оценка страны выхода — сервер считает её в country.py, тут только показываем */
const TIER={trusted:['✅','надёжная'],good:['🟢','нормальная'],neutral:['⚪','нейтральная'],
  risky:['⚠️','рискованная'],disputed:['❓','спорная'],blocked:['⛔','запрещена']};
function tierBadge(t,hint){const d=TIER[t]||TIER.neutral;
  return '<span class="pill'+(t=='trusted'||t=='good'?' ok':(t=='risky'||t=='blocked'?' bad':(t=='disputed'?' warn':'')))+
    '" title="'+esc(hint||'')+'">'+d[0]+' '+d[1]+'</span>'}
/* подпись страны глазами АКТИВНОЙ стратегии (приёмка №7): при «Скорость и отклик»
   страна на оценку не влияет — тревожить «спорной» не за что. Оценка самой страны
   (внутренний рейтинг) остаётся в подсказке. */
function ccBadge(p){
  if(p.cc_mode==='ignored')return '<span class="pill" style="opacity:.55" title="'+
    esc('стратегия «Скорость и отклик»: страна в оценке не участвует, решают замеры. Для справки: '+(p.cc_hint||''))+
    '">⏱ не влияет</span>';
  return tierBadge(p.cc_tier,p.cc_hint)}
function ccWarn(s){const t=s.cc_tier;
  if(t!=='risky'&&t!=='disputed')return '';
  return ' ⚠️ Оценка страны выхода — '+(TIER[t]||[])[1]+': '+(s.cc_hint||'')+
    '. В таблице ниже видно оценку каждого прокси: выбери с пометкой «надёжная» и нажми «Применить».'}

/* ── возраст последней пробы, человеческим языком ── */
function agoTxt(sec){if(sec==null)return '';
  if(sec<90)return 'только что';if(sec<5400)return Math.max(1,Math.floor(sec/60))+' мин назад';
  if(sec<172800)return Math.floor(sec/3600)+' ч назад';return Math.floor(sec/86400)+' дн назад'}
const STALE=900;   // 15 мин — после этого метку считаем несвежей

/* ── маяк: одно предложение о том, всё ли хорошо ── */
function beacon(s,clients){
  const b=document.getElementById('beacon');let cls,ttl,txt;
  const n=(clients==null?null:clients);
  const who=n==null?'':(' Устройств с доступом: '+n+'.');
  const when=s.egress_at?(' Проверено '+agoTxt(s.egress_age)+'.'):'';
  const stale=(s.egress_age!=null&&s.egress_age>STALE);
  if(s.emergency){cls='b-bad';ttl='Аварийный режим включён';
    txt='Клиенты в интернете, но выходят с российского IP самого сервера — блокировки НЕ обходятся. '+
        'Это временно: нажми «Ротация», чтобы вернуться на зарубежный прокси, потом сними аварию.'+who}
  else if(s.automat==='ROTATING'){cls='b-warn';ttl='Перебираю пул прокси';
    txt='Боевой прокси умер — панель перебирает запасные из пула (это НЕ авария). На время перебора '+
        'клиенты выходят напрямую через сервер, с российского IP. Обычно занимает пару минут; '+
        'вмешиваться не нужно.'+who}
  else if(s.automat==='DEGRADED'){cls='b-warn';ttl='Канал жив, Telegram недоступен';
    txt='Интернет через прокси работает'+(s.egress?(' (выход '+esc(s.egress)+')'):'')+', но api.telegram.org не отвечает — '+
        'у клиентов может молчать Telegram. Прокси менять не из-за чего: он жив, сбой на стороне Telegram/провайдера.'+who}
  else if(s.automat==='SUSPECT'){cls='b-warn';ttl='Перепроверяю сбой';
    txt='Первая проверка выхода не прошла — панель подтверждает сбой повторной, прежде чем что-то менять. '+
        'Единичный сетевой чих аварией не считается.'+who}
  else if(window.__EGBUSY){cls='b-warn';ttl='Проверяю выход…';
    txt='Спрашиваю у внешнего сайта, какой IP видно с сервера. Это занимает несколько секунд.'+who}
  else if(!s.egress_at){cls='b-warn';ttl='Состояние ещё не проверялось';
    txt='Панель ни разу не спрашивала, какой IP видят сайты. Нажми «Проверить выход» — это безопасно.'+who}
  else if(!s.egress_ok&&s.egress&&/^Telegram/.test(s.egress_why||'')){cls='b-warn';ttl='Канал жив, Telegram недоступен';
    txt='Выход в интернет работает ('+esc(s.egress)+'), но api.telegram.org не отвечает — у клиентов может молчать '+
        'Telegram. Прокси жив, менять его не из-за чего.'+when+who}
  else if(s.egress_ok){const w=ccWarn(s);cls=w?'b-warn':'b-ok';ttl=w?'Работает, но страна выхода необычная':'Всё работает';
    txt='Трафик выходит в интернет через прокси '+esc(s.egress)+(s.egress_cc?(' — '+country(s.egress_cc)):'')+
        '. Именно этот IP видят сайты.'+when+who+w+
        (stale?' Данные не первой свежести — нажми «Проверить выход», чтобы обновить.':'')}
  else if(stale){cls='b-warn';ttl='Данные устарели — перепроверяю';
    txt='Последняя проверка ('+agoTxt(s.egress_age)+') говорила, что выход не работал. '+
        'С тех пор автоматика могла всё починить сама, поэтому панель прямо сейчас проверяет заново.'+who}
  else{cls='b-bad';ttl='Цепочка нарушена';
    txt='Сайты видят '+(s.egress?('IP '+esc(s.egress)):'пустоту')+', а должен быть адрес зарубежного прокси'+
        (s.egress_why?(' ('+esc(s.egress_why)+')'):'')+'. Нажми «Ротация» — панель сама переберёт варианты.'+when+who}
  if(cls==='b-ok'&&s.frozen){cls='b-warn';ttl='Работает, но автоматика на паузе';
    txt='Сейчас связь есть, однако сама чинить себя панель не будет — переключать прокси придётся руками.'+when+who}
  else if(s.frozen&&cls!=='b-ok'){ttl+=' · автоматика на паузе';
    txt+=' ⏸ Автоматика на паузе: сама не починится, пока паузу не снимешь (кнопка сверху).'}
  b.className='beacon '+cls;
  b.innerHTML='<div class="dot"></div><div><div class="ttl">'+ttl+'</div><div class="txt">'+txt+'</div></div>'}

async function loadStatus(){const s=await api('/api/status');window.__S=s;
  document.getElementById('subline').textContent=
    'узел '+s.role+' · Редут '+(s.version||'?')+' · сеть '+s.subnet+' · sing-box '+s.singbox+' · прокси в пуле: '+s.pool_alive;
  /* заголовок свернутой карточки стратегий: название активной — из статуса,
     дорогой GET /api/strategy при этом не дёргается (П4) */
  const sn=document.getElementById('stnow');if(sn)sn.textContent=s.strategy_title||'';
  fillBuyCC();
  document.getElementById('ts').textContent='обновлено '+new Date().toLocaleTimeString('ru-RU');
  const cur=s.upstream||{};
  const AUTL={ROTATING:'перебор пула',DEGRADED:'TG недоступен, канал жив',SUSPECT:'перепроверяю сбой'};
  const aut=s.emergency?('<span class="bad">АВАРИЯ'+(s.emergency_since?(' с '+esc(s.emergency_since)):'')+'</span>')
    :(AUTL[s.automat]?('<span class="warn">'+AUTL[s.automat]+'</span>')
    :(s.frozen?'<span class="warn">на паузе</span>':'<span class="ok">'+esc(s.automat||'OK')+'</span>'));
  document.getElementById('status').innerHTML=[
    tile('автоматика',aut,'Сторож проверяет связь и, если прокси умер, сам переключает на живой или докупает новый. «На паузе» — не вмешивается.'),
    tile('прокси на выходе',esc(cur.socks_out||'?'),'Зарубежный прокси, через который сервер выпускает трафик наружу. Технически — SOCKS5-upstream.'),
    tile('канал telegram',esc(cur.http_tg||'?'),'Telegram ходит отдельным http-каналом того же прокси — так надёжнее.'),
    tile('IP на выходе',window.__EGBUSY?'<span class="mut">проверяю…</span>':
      (s.egress_at?('<span class="'+(s.egress_ok?'ok':'bad')+'">'+esc(s.egress||'нет ответа')+
        (s.egress_cc?(' · '+country(s.egress_cc)):'')+'</span>'+
        '<div class="sub" style="font-size:10px">проверено '+agoTxt(s.egress_age)+'</div>')
      :'<span class="mut">нажми «Проверить выход»</span>'),
      'Адрес, который видят сайты. Должен совпадать с прокси на выходе — тогда цепочка цела. Проверка живая и небыстрая, поэтому панель показывает результат последней: свою (кнопка) или сделанную автоматикой.'),
    tile('баланс у провайдера',Object.entries(s.balances||{}).map(([k,v])=>k+': '+v).join(' · ')||'—',
      'Деньги в кабинете провайдера прокси. Кончатся — панель не сможет докупить замену.'),
    tile('пульс автоматики',s.heartbeat?esc(s.heartbeat):'<span class="mut">нет</span>',
      'Когда сторож последний раз отчитывался. Пусто сразу после установки — появится в течение часа.'),
  ].join('');
  const eb=document.getElementById('embtn');
  if(eb){eb.textContent=s.emergency?'Снять аварию':'Аварийный режим';eb.className='btn '+(s.emergency?'g':'r');}
  const fb=document.getElementById('frbtn');
  if(fb){fb.textContent=s.frozen?'▶ Возобновить автоматику':'⏸ Пауза автоматики';
    fb.className='btn '+(s.frozen?'a':'s')}
  beacon(s,window.__CN);
  /* сводки в шапках: свёрнутый раздел всё равно говорит главное */
  sum('pool','живых прокси: '+(s.pool_alive==null?'?':s.pool_alive)+
    (s.switch_busy?' · переключаю боевой канал…':''));
  sum('money',Object.entries(s.balances||{}).map(([k,v])=>k+': '+v).join(' · '));
  sum('upd','Редут '+(s.version||'?'));
  geoSync(s);
  maybeRecheck(s)}

/* F7: пауза автоматики (FROZEN) — сторож ничего не делает сам, пока не снимешь */
async function doFreeze(){const to=!((window.__S||{}).frozen);
  if(!confirm(to?'Поставить автоматику на паузу?\\n\\nСторож перестанет сам переключать прокси, покупать и включать аварийный режим. Узел будет чиниться только руками, пока паузу не снимешь.'
    :'Возобновить автоматику?\\n\\nСторож снова будет сам чинить канал: переключать прокси, докупать и включать аварийный режим при необходимости.'))return;
  try{const r=await api('/api/automat',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({frozen:to})});
    toast(r.frozen?'Автоматика на паузе — не забудь снять после работ':'Автоматика снова работает',r.frozen?'warn':'ok');
    await loadStatus()}catch(e){toast(e.message,'bad')}}

/* Сама перепроверяет выход, если метка отсутствует или протухла.
   Зачем: метку пишут агент (egress-mark раз в 5 мин, полный verify раз в 30 мин) и
   действия человека. Если узел сам починился
   между записями, в панели висела бы старая ошибка — так и случилось 15.08, когда
   «цепочка нарушена» держалась ещё полчаса после того, как всё заработало.
   Не чаще раза в 2 минуты, чтобы не устраивать шторм проб. */
function maybeRecheck(s){
  if(window.__EGBUSY)return;
  const now=Date.now();
  if(window.__EGLAST&&now-window.__EGLAST<120000)return;
  const нет=!s.egress_at, старая=(s.egress_age!=null&&s.egress_age>STALE), плохая=(s.egress_at&&!s.egress_ok);
  if(нет||старая||плохая){window.__EGLAST=now;egress(true)}}

async function loadPool(){const rows=(await api('/api/pool')).proxies;const tb=document.querySelector('#pool tbody');tb.innerHTML='';
  /* П1: строки запрещённых стран не рендерим вовсе — только счётчик под таблицей,
     чтобы купленное не исчезало молча. Исключение: заблокированный боевой виден всегда. */
  const hidden=rows.filter(p=>p.blocked&&!p.is_current);
  const shown=rows.filter(p=>!p.blocked||p.is_current);
  const hb=document.getElementById('poolhidden');
  if(hb)hb.textContent=hidden.length?('скрыто '+hidden.length+' '+(hidden.length===1?'прокси':'прокси')+
    ' из запрещённых стран ('+hidden.map(p=>country(p.exit_cc||p.country)).join(', ')+') — панель их не использует'):'';
  for(const p of shown){const tr=document.createElement('tr');if(p.is_current)tr.className='cur';
    const roles=['auto','off'];
    const inact=!p.provider_active;
    const cc=p.exit_cc||p.country;
    const id=esc(p.uid).replace(/^proxy6:|^proxyline:/,'');
    const sold=(p.exit_cc&&p.country&&p.exit_cc!=p.country)?'продан как '+esc(country(p.country)):'';
    const argue=(p.geo_agree===false)?'спор: '+esc(country(p.exit_cc))+'/'+esc(country(p.exit_cc_alt)):'';
    const note=sold||argue;
    const ports=(p.port_socks5||'—')+(p.port_http&&p.port_http!=p.port_socks5?('/'+p.port_http):'');
    tr.innerHTML=
      '<td>'+id+(p.is_current?' <span class="pill ok">боевой</span>':'')+(p.gone?' <span class="pill bad">пропал</span>':'')+
        (inact?' <span class="pill warn" title="Ключ провайдера удалён: панель этим прокси не управляет. Боевой канал будет переключён по стратегии автоматически.">без ключа</span>':'')+
        '<div class="sub" style="font-size:10px">'+esc(p.provider)+'</div></td>'+
      '<td>'+esc(country(cc)||'??')+' '+ccBadge(p)+
        (note?'<div class="sub" style="font-size:10px">'+note+'</div>':'')+'</td>'+
      '<td>'+esc(p.host)+'<div class="sub" style="font-size:10px">порт '+ports+'</div></td>'+
      '<td>'+(p.score==null?'—':p.score)+
        (p.latency!=null?'<div class="sub" style="font-size:10px">'+p.latency+' мс</div>':'')+
        '<div class="flags" style="font-size:11px">'+
        fl(p.socks_ok)+fl(p.http_ok)+fl(p.tg_ok)+'</div></td>'+
      '<td>'+(p.days==null?'—':p.days+' дн')+
        '<div class="sub" style="font-size:10px">'+(p.last_probe?('тест '+esc(p.last_probe)):'не проверялся')+'</div></td>'+
      '<td><select data-uid="'+esc(p.uid)+'" onchange="setRole(this)">'+
        roles.map(r=>'<option'+(r==p.role?' selected':'')+'>'+r+'</option>').join('')+'</select></td>'+
      '<td><button class="btn s tiny" onclick="probe(this,\\''+esc(p.uid)+'\\')" title="Проверить прокси — безопасно, ничего не меняет">Тест</button> '+
        '<button class="btn g tiny" onclick="apply(this,\\''+esc(p.uid)+'\\')"'+(inact?' disabled':'')+
        ' title="'+(inact?'У провайдера нет ключа — панель не управляет этим прокси':'Сделать боевым: проверка → переключение → проверка → автооткат при провале. Для off после успеха роль станет auto')+'">В бой</button> '+
        '<button class="btn a tiny" onclick="prolong(this,\\''+esc(p.uid)+'\\')"'+(inact?' disabled':'')+
        ' title="'+(inact?'У провайдера нет ключа — продлить нечем':'Продлить аренду — тратит деньги')+'">Продлить</button> '+
        '<button class="btn r tiny" onclick="del(this,\\''+esc(p.uid)+'\\')"'+((p.provider!='proxy6'||inact)?' disabled':'')+
        ' title="Удалить навсегда">Удалить</button></td>';
    tb.appendChild(tr)}
  if(!rows.length)tb.innerHTML='<tr><td colspan="7" class="mut">пул пуст — панель ещё не знает ни одного прокси. '+
    'Если ключ провайдера уже введён, нажми «Обновить пул»; если нет — впиши его ниже, в разделе '+
    '«Ключи провайдеров прокси».</td></tr>'}

async function loadEvents(){const evs=(await api('/api/events?limit=40')).events;const tb=document.querySelector('#events tbody');tb.innerHTML='';
  for(const e of evs){const tr=document.createElement('tr');
    tr.innerHTML='<td class="mut">'+esc(e.ts)+'</td><td>'+esc(e.actor)+'</td><td>'+esc(e.action)+'</td>'+
      '<td class="'+(/ok/.test(e.result)?'ok':(/fail/.test(e.result)?'bad':''))+'">'+esc(e.result)+'</td>'+
      '<td class="mut" title="'+esc(e.detail)+'">'+esc((e.detail||'').slice(0,80))+'</td>';tb.appendChild(tr)}
  if(!evs.length)tb.innerHTML='<tr><td colspan="5" class="mut">событий пока нет</td></tr>'}

async function loadMoney(){try{const m=await api('/api/money');const L=m.limits||{},t=m.today||{};
  /* F8: чему узел научился — надёжность пар (провайдер, страна) по своему опыту */
  const st=(m.stability||[]);const sb=document.getElementById('stabbox');
  if(sb)sb.innerHTML=st.length?('Надёжность по опыту узла: '+st.map(x=>{
    const lbl=country(x.country)+(x.provider!=='proxy6'?(' ('+esc(x.provider)+')'):'')+' '+x.rel_pct+'% ('+
      x.probes+' проб, '+x.days+' дн'+(x.drops?(', обрывов '+x.drops):'')+')';
    return x.learning?('<span class="mut" title="данных ещё мало — пара не влияет на выбор покупки">'+esc(lbl)+' · учусь</span>')
      :('<span title="бонус к выбору страны при покупке: '+esc(''+x.bonus)+'">'+esc(lbl)+'</span>')}).join(' · ')):'';
  document.getElementById('money').innerHTML=[
    tile('покупок сегодня',(t.buys||0)+' из '+L.max_buys_per_day,'Больше этого числа панель за сутки не купит — ни сама, ни по кнопке.'),
    tile('потрачено сегодня',(t.spent_rub||0)+' / '+L.max_spend_per_day+' ₽','Дневной потолок трат.'),
    tile('потолок одной покупки','до '+L.max_price_per_buy+' ₽','Прокси дороже этой цены не купится.'),
    tile('неснижаемый остаток','от '+L.min_balance_reserve+' ₽','Ниже этой суммы на балансе покупки прекращаются.'),
    tile('покупка / удаление',(L.buy_enabled?'<span class="ok">разрешена</span>':'<span class="bad">запрещена</span>')+
      ' / '+(L.delete_enabled?'<span class="warn">разрешено</span>':'запрещено'),
      'Тумблеры в конфиге на сервере. Пока покупка запрещена, автоматика не потратит ни рубля.'),
    apTile(),
    stTile(),
  ].join('')}catch(e){}}
/* какое правило выбора стран сейчас действует — подробности в карточке ниже */
function stTile(){const s=window.__S||{};
  return tile('стратегия стран',esc(s.strategy_title||'—'),
    (s.strategy_short?(s.strategy_short+'. '):'')+
    'Правило, как панель выбирает между надёжной страной и хорошими замерами: где ей разрешено '+
    'покупать и в каком порядке перебирать пул. Меняется в карточке «Стратегия выбора стран» ниже.')}
/* автопродление «якоря» — состояние берём из /api/status */
function apTile(){const a=(window.__S||{}).auto_prolong;
  if(!a)return tile('автопродление','<span class="mut">—</span>','Панель ещё не сообщила настройки.');
  return tile('автопродление боевого',
    a.enabled?('<span class="ok">вкл</span> · за '+a.days_before+' дн · +'+a.period_days+' дн')
             :'<span class="warn">выкл</span>',
    'Продлевает срок аренды боевого прокси, пока он здоров, — чтобы IP не менялся. Смена адреса стоит столько же, '+
    'сколько продление, но новый IP «холодный»: сайты начинают требовать перелогины, капчи и подтверждения оплаты. '+
    'Если продлить не выйдет (лимит, баланс, сбой у провайдера) — придёт письмо, молча истечь не даст.')}

async function market(){await openFold('money');toast('Спрашиваю провайдера, что есть в продаже…');try{const m=await api('/api/market');window.__MARKET=m;const box=document.getElementById('marketbox');
  const pr=m.price?('цена '+m.price.price+' '+m.price.currency+' за 1 шт × '+m.period+' дн · баланс '+m.price.balance):(m.price_error||'цена недоступна');
  box.textContent=(m.country_error?('рынок недоступен ('+m.country_error+') · '):
    ('Доступные страны ('+(m.available||[]).length+'): '+((m.available||[]).map(a=>country(a.cc)).join(', ')||'—')+' · '))+pr;
  fillBuyCC();
  toast('Список обновлён','ok')}catch(e){toast(e.message,'bad')}}

/* ── форма покупки (приёмка №7): белого списка больше нет ──
   Опции — ВСЕ страны провайдера в продаже (кроме чёрного списка), отранжированы
   внутренним рейтингом на сервере, с пометкой оценки (✅/🟢/⚪/⚠️);
   пока рынок не спрошен или недоступен — полный словарь стран минус чёрный список;
   «другая страна…» открывает свободный ввод (сервер валидирует сам). */
function buyccChange(sel){document.getElementById('buyccfreebox').style.display=(sel.value==='__other__')?'':'none'}
function fillBuyCC(){const s=window.__S||{};const m=window.__MARKET||null;
  const sel=document.getElementById('buycc');if(!sel)return;
  if(document.activeElement===sel)return; /* не пересобирать открытый список под руками (loadStatus идёт каждые 30 с) */
  const cur=sel.value;
  const bl=new Set(s.cc_blacklist||[]);
  let list,suffix='';const tiers={};
  if(m&&!m.country_error&&(m.available||[]).length){
    list=(m.available||[]).map(a=>{tiers[a.cc]=a.tier;return a.cc}).filter(c=>!bl.has(c))}
  else{list=Object.keys(CC).filter(c=>!bl.has(c));
    if(m&&m.country_error)suffix=' · рынок недоступен, страна не проверена'}
  const opts=['<option value="">— панель выберет сама —</option>'];
  for(const c of list){const t=TIER[tiers[c]];
    opts.push('<option value="'+esc(c)+'"'+(cur===c?' selected':'')+'>'+
      esc(country(c))+(t?(' '+t[0]):'')+esc(suffix)+'</option>')}
  opts.push('<option value="__other__"'+(cur==='__other__'?' selected':'')+'>другая страна…</option>');
  sel.innerHTML=opts.join('')}

async function buy(){const _sel=document.getElementById('buycc');
  const cc=(_sel.value==='__other__'?(document.getElementById('buyccfree').value||''):_sel.value).trim().toLowerCase();
  const per=document.getElementById('buyperiod').value.trim();
  if(!confirm('Купить прокси'+(cc?(' в стране '+cc):' (страну выберет панель)')+(per?(', на '+per+' дн'):'')+'?\\n\\n'+
    'Спишутся РЕАЛЬНЫЕ деньги с баланса у провайдера. После покупки панель сама проверит, из какой страны реально выходит прокси.'))return;
  toast('Покупаю: узнаю цену → покупка → проверка…');try{const b={};if(cc)b.country=cc;if(per)b.period=parseInt(per);
    const r=await api('/api/buy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
    const pc=(r.postcheck||[]).map(x=>x.uid+' страна выхода '+(x.exit_cc||'?')+(x.blocked?' → заблокирован, роль off':' → годен')).join('; ');
    toast('Куплено: '+(r.uids||[]).join(',')+' за '+r.price+' '+r.currency+(r.recovered?' (восстановлено по описанию)':'')+'. '+pc+
      (r.warning?(' ⚠️ '+r.warning):''),r.warning?'warn':'ok');await reloadAll()}
  catch(e){toast('покупка: '+e.message,'bad');await reloadAll()}}

async function prolong(btn,uid){const d=prompt('На сколько дней продлить '+uid+'?\\nСпишутся реальные деньги.','30');if(!d)return;
  btn.disabled=true;toast('Продлеваю '+uid+'…');try{const r=await api('/api/proxy/'+encodeURIComponent(uid)+'/prolong',
    {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:parseInt(d)})});
    toast('Продлён '+uid+' на '+r.days+' дн · '+r.price+' '+r.currency+' · действует до '+(r.date_end||'?'),'ok');await reloadAll()}catch(e){toast(e.message,'bad')}btn.disabled=false}

async function del(btn,uid){if(!confirm('Удалить прокси '+uid+' НАВСЕГДА?\\n\\nСервер пропустит удаление, только если: удаление разрешено тумблером, '+
    'прокси не боевой, он дважды провалил проверку и сам провайдер считает его нерабочим.'))return;
  btn.disabled=true;toast('Удаляю '+uid+'…');try{const r=await api('/api/proxy/'+encodeURIComponent(uid)+'/delete',{method:'POST'});
    toast('Удалено: '+r.deleted+' ('+uid+')','ok');await reloadAll()}catch(e){toast('удаление: '+e.message,'bad')}btn.disabled=false}

/* ── стратегия выбора стран: правило «страна против замеров» ──
   Тексты стратегий приходят с сервера (country.STRATEGIES) — там же, где сама логика,
   чтобы описание в панели не разошлось с поведением. */
async function loadStrategy(){try{const r=await api('/api/strategy');
  document.getElementById('stmeta').textContent='пул для выбора: '+r.pool_size+' шт · запрещено навсегда: '+
    (r.blacklist||[]).map(country).join(', ');
  document.getElementById('strategies').innerHTML=(r.strategies||[]).map(s=>{
    /* П3: строка «Сейчас с ней» обязана быть стратегийно-разной — и по правилу
       докупки, и по судьбе стран нынешнего пула, и по выбору канала */
    const names=a=>(a||[]).map(country).join(', ');
    const more=(s.buy_total||0)>(s.buy||[]).length?' и ещё '+(s.buy_total-(s.buy||[]).length):'';
    let buy;
    if(s.buy_mode==='gated')buy='сама докупает только надёжные: '+(names(s.buy)||'—')+more+
      (s.pool_block&&s.pool_block.length?'; страны пула '+names(s.pool_block)+' сама не купит (вручную — можно)':'');
    else buy='сама докупает везде, кроме запрещённых'+
      (s.pool_pass&&s.pool_pass.length?' — страны пула ('+names(s.pool_pass)+') разрешены':'')+
      '; сначала пробует: '+(names((s.buy||[]).slice(0,4))||'—');
    const pick=s.pick?(esc(s.pick.host)+(s.pick.cc?(' · '+country(s.pick.cc)):'')+
      (s.pick.is_current?' — текущий канал, останется':' — сменило бы при ближайшей ротации')):'пул пуст';
    return '<div class="step" style="margin-top:10px'+(s.current?';border-color:rgba(5,255,161,.45);background:rgba(5,255,161,.05)':'')+'">'+
      '<b>'+esc(s.title)+'</b>'+
      (s.current?'<span class="pill ok">включена сейчас</span>':'<span class="pill">'+esc(s.short)+'</span>')+
      '<div class="sub" style="margin-top:7px;white-space:normal">'+esc(s.desc)+'</div>'+
      '<div class="sub" style="margin-top:7px;white-space:normal">Сейчас с ней: '+buy+
      '; из нынешнего пула выбрало бы <b>'+pick+'</b></div>'+
      (s.current?'':'<div style="margin-top:9px"><button class="btn g" onclick="setStrategy(\\''+esc(s.id)+
        '\\',\\''+esc(s.title)+'\\')">Включить</button></div>')+
      '</div>'}).join('')}
  catch(e){document.getElementById('strategies').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}

async function setStrategy(id,title){
  if(!confirm('Включить стратегию «'+title+'»?\\n\\nТекущий канал продолжит работать — правило применится '+
    'при следующей смене прокси (ротация, «В бой», покупка). Числа и порядок в таблице пула '+
    'пересчитаются сразу, без новой проверки.'))return;
  try{const r=await api('/api/strategy',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({strategy:id})});
    toast(r.changed?('Стратегия: «'+title+'» включена'):'Эта стратегия и так была включена','ok');
    await loadStrategy();await loadStatus();await loadMoney();await loadPool()}
  catch(e){toast('стратегия: '+e.message,'bad')}}

/* ── ключи провайдеров: вписать или заменить прямо здесь ──
   Сам ключ панель обратно не отдаёт: показываем только хвост, который приходит с сервера. */
const PROV={
  proxy6:{t:'PROXY6',h:'Основной провайдер: панель умеет у него всё — купить, продлить, удалить; цены в рублях. '+
    'Ключ: кабинет proxy6.net → раздел «API». Если в кабинете включено ограничение API по IP, впиши туда адрес '+
    'этого сервера, иначе провайдер ответит «доступ с неверного IP».'},
  proxyline:{t:'ProxyLine',h:'Запасной провайдер: через API панель умеет только продлевать (купить и удалить нельзя), '+
    'цены в долларах. Ключ: кабинет panel.proxyline.net → раздел «API».'}};
async function loadKeys(){try{const r=await api('/api/key/status');
  document.getElementById('keys').innerHTML=(r.providers||[]).map(p=>{const m=PROV[p.provider]||{};
    return '<div class="step" style="margin-top:10px">'+
      '<b>'+esc(m.t||p.provider)+'</b>'+
      (p.set?('<span class="pill ok">ключ задан · '+esc(p.masked)+'</span>')
            :('<span class="pill warn">ключ не задан</span>'))+
      ' <span class="pill">прокси в пуле: '+p.alive+'</span>'+
      (p.balance?(' <span class="pill">баланс '+esc(p.balance)+'</span>'):'')+
      '<div class="sub" style="margin-top:7px;white-space:normal">'+esc(m.h||'')+'</div>'+
      '<div class="field" style="margin-top:9px">'+
        '<div style="flex:1;min-width:230px"><label>'+(p.set?'заменить ключ':'вписать ключ')+'</label>'+
        '<input id="k_'+esc(p.provider)+'" autocomplete="off" placeholder="вставь ключ из кабинета"></div>'+
        '<button class="btn g" onclick="saveKey(\\''+esc(p.provider)+'\\')">Сохранить</button>'+
        (p.set?('<button class="btn s" onclick="checkKey(\\''+esc(p.provider)+'\\')" '+
                 'title="Спросить у провайдера баланс этим ключом — безопасно, ничего не меняет">Проверить</button>'+
                '<button class="btn r" onclick="delKey(\\''+esc(p.provider)+'\\')">Убрать</button>'):'')+
      '</div></div>'}).join('')||'<span class="mut">провайдеры не заданы</span>'}
  catch(e){document.getElementById('keys').innerHTML='<span class="bad">'+esc(e.message)+'</span>'}}

async function saveKey(p){const el=document.getElementById('k_'+p);const k=(el.value||'').trim();
  if(!k)return toast('вставь ключ в поле слева от кнопки','bad');
  if(!confirm('Сохранить новый ключ '+p+'?\\n\\nПанель сразу проверит его у провайдера. Дальше все покупки '+
    'и продления — и твои, и автоматики — пойдут через этот кабинет.'))return;
  const body=JSON.stringify({provider:p,key:k});
  toast('Проверяю ключ у провайдера…');
  try{let r=await api('/api/key',{method:'POST',headers:{'Content-Type':'application/json'},body:body});
    if(r.needs_force){
      if(!confirm('Провайдер сейчас не отвечает серверу, поэтому проверить ключ не вышло:\\n\\n'+(r.error||'')+
        '\\n\\nСохранить ключ без проверки? Узел умеет ходить к API провайдера через собственный зарубежный '+
        'канал — тогда ключ заработает сам, как только канал поднимется.'))return;
      r=await api('/api/key',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({provider:p,key:k,force:true})})}
    el.value='';
    toast(r.verified?('Ключ '+p+' сохранён и проверен — баланс '+r.balance+' '+(r.currency||''))
                    :('Ключ '+p+' сохранён без проверки: '+(r.error||'провайдер недоступен')),r.verified?'ok':'warn');
    await loadKeys();await loadStatus()}
  catch(e){toast('ключ: '+e.message,'bad')}}

async function checkKey(p){toast('Спрашиваю у '+p+' баланс этим ключом…');
  try{const r=await api('/api/key/check',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({provider:p})});
    toast(r.ok?('Ключ '+p+' рабочий — баланс '+r.balance+' '+(r.currency||''))
              :('Ключ '+p+' не сработал: '+(r.error||'')+
                (r.network?' Похоже на недоступность сервиса с сервера, а не на плохой ключ.':'')),r.ok?'ok':'bad');
    await loadKeys();if(r.ok)await loadStatus()}catch(e){toast(e.message,'bad')}}

async function delKey(p){if(!confirm('Убрать ключ '+p+' из панели?\\n\\nЕго прокси будут сразу УДАЛЕНЫ из пула — '+
    'покупать, продлевать и проверять их панели больше нечем. Сам кабинет у провайдера и уже оплаченные '+
    'прокси никуда не денутся.\\n\\nЕсли боевой канал сейчас на этом провайдере — панель сама переключит его '+
    'на другого провайдера по текущей стратегии (проверка → переключение → проверка → автооткат).\\n\\n'+
    'Последний оставшийся ключ убрать нельзя — без него панель слепа.'))return;
  try{const r=await api('/api/key',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({provider:p,key:''})});
    toast('Ключ '+p+' убран'+(r.purged?(': '+r.purged+' его прокси удалены из пула'):'')+
      (r.warning?('. ⚠️ '+r.warning):''),r.warning?'warn':'ok');
    await loadKeys();await loadPool();await loadStatus()}catch(e){toast(e.message,'bad')}}

/* ── обновления с GitHub (UPDATE-PLAN): версия узла против маяка ── */
function updWhen(ts){return ts?esc(String(ts).replace('T',' ')):'ещё не проверялось'}
const UPD_PH={check:'проверяю версию',download:'скачиваю выпуск',backup:'откладываю прежнюю сборку',
  install:'устанавливаю (пара минут)',verify:'проверяю узел после установки',rollback:'ОТКАТЫВАЮСЬ на прежнюю версию'};
/* прогресс-бар хода обновления (1.6.0): проценты по фазам update.py; внутри фазы
   точных процентов нет (setup.sh — чёрный ящик), поэтому бар «дышит» анимацией */
const UPD_PCT={check:6,download:22,backup:40,install:68,verify:88,rollback:88,done:100,failed:100};
const UPD_STEPS=[['download','скачивание'],['backup','резерв'],['install','установка'],['verify','проверка']];
function updBar(live){const ph=live.phase||'check';
  const bad=(ph==='rollback'||ph==='failed');
  const pct=UPD_PCT[ph]!=null?UPD_PCT[ph]:10;
  let idx=UPD_STEPS.findIndex(s=>s[0]===ph);
  if(idx<0)idx=(ph==='done')?UPD_STEPS.length:(bad?UPD_STEPS.length-1:0);
  const steps=UPD_STEPS.map((s,i)=>{
    let cls=i<idx?'done':(i===idx?'act':'');
    if(bad&&i>=idx)cls='bad';
    return '<span class="pstep '+cls+'">'+s[1]+'</span>'}).join('');
  const what=(live.frm||live.to)?((live.frm?esc(live.frm):'?')+' → '+esc(live.to||'?')):'';
  return '<div class="pwrap">'+
    '<div class="pbar"><div class="pfill'+(bad?' bad':(ph==='done'?' ok':''))+'" style="width:'+pct+'%"></div>'+
      '<div class="plabel">'+esc(UPD_PH[ph]||ph)+(what?(' · '+what):'')+'</div></div>'+
    '<div class="psteps">'+steps+'</div>'+
    '<div class="sub" style="margin-top:6px">'+
    (bad?('<span class="bad">'+esc(live.why||'проверка не прошла')+'</span> — узел возвращается на прежнюю версию, карточка покажет итог')
        :'панель может ненадолго перезапуститься — карточка сама дочитает итог')+
    '</div></div>'}
async function loadUpd(){let r;try{r=await api('/api/update/status')}
  catch(e){ /* панель могла перезапускаться посреди обновления — тихо пробуем ещё */
    if(window.__UPDBUSY&&!window.__UPDPOLL){window.__UPDPOLL=1;
      setTimeout(async()=>{window.__UPDPOLL=0;try{await loadUpd()}catch(_){}},3000);return}
    document.getElementById('upd').innerHTML='<span class="bad">'+esc(e.message)+'</span>';return}
  window.__UPD=r;
  const live=r.live||{};const busy=!!r.applying;
  const tiles=[
    tile('на узле','Редут '+esc(r.local||'?'),'Версия сборки, которая работает прямо сейчас.'),
    tile('последний выпуск',
      r.latest?('Редут '+esc(r.latest)+' '+(r.newer?(r.bad?'<span class="pill bad">проблемный</span>':'<span class="pill warn">новее</span>')
        :(r.local===r.latest?'<span class="pill ok">он и стоит</span>'
          :(r.local?'<span class="pill">старее узла</span>':'<span class="pill warn">версия узла неизвестна</span>'))))
              :'<span class="mut">ещё не проверялось</span>',
      'Что лежит в официальном репозитории (файл VERSION на GitHub). Проверка идёт раз в сутки и по кнопке.'),
    tile('проверялось',updWhen(r.last_check)+(r.last_error?' <span class="bad">ошибка</span>':''),
      'Когда узел последний раз спрашивал GitHub. Разовая ошибка сети не страшна — следующая проверка по расписанию.'),
    tile('автообновление',(r.auto?'<span class="ok">включено</span>':'<span class="warn">выключено</span>')+
      '<div class="sub" style="font-size:10px">окно '+esc(r.window||'')+' по времени сервера'+
      (r.auto&&r.window_ok===false?' <span class="bad">не накрывает время проверки 04:41–05:06 — авто не сработает!</span>':'')+'</div>',
      'Включено — узел сам ставит новую версию ночью, в указанное окно. Выключено — только письмо о новинке, обновлять руками. Окно правится в /etc/vpn-panel/config.json (update.window).'),
  ];
  document.getElementById('upd').innerHTML=tiles.join('');
  const box=document.getElementById('updbox');
  const la=r.last_apply||null;
  if(busy){box.innerHTML='<span class="warn">Идёт обновление</span>'+updBar(live)}
  else if(r.last_error){box.innerHTML='<span class="warn">Последняя проверка не удалась: '+esc(r.last_error)+'</span>'}
  else if(r.newer&&r.bad){box.innerHTML='<span class="bad">Версия '+esc(r.latest)+' в чёрном списке: обновление на неё уже проваливалось и было откатано. Автоматика её не тронет.</span>'}
  else if(r.newer){box.innerHTML='<span class="warn">Доступна версия '+esc(r.latest)+'.</span> '+(r.auto?'Узел сам обновится в окно '+esc(r.window)+'.':'Автообновление выключено — обнови вручную.')}
  else if(la&&!la.ok){box.innerHTML='<span class="mut">Последняя попытка '+updWhen(la.ts)+': '+esc(la.from||'?')+' → '+esc(la.to||'?')+' не прошла ('+esc(la.why||'')+'), '+(la.rolled_back?'откат выполнен':'откат НЕ подтвердился — глянь узел руками')+'.</span>'}
  else{box.textContent=''}
  const act=document.getElementById('updact');
  if(busy){act.innerHTML=''}
  else{let b='';
    if(r.newer&&!r.bad)b='<button class="btn g" onclick="applyUpd(this)">Обновить сейчас до '+esc(r.latest)+'</button> ';
    else if(r.newer&&r.bad)b='<button class="btn r" onclick="applyUpd(this)" title="Прошлая попытка провалилась и была откатана. Ставить повторно имеет смысл, только если понимаешь, что тогда пошло не так.">Поставить '+esc(r.latest)+' несмотря на прошлый провал</button> ';
    else if(r.latest&&r.local&&r.latest===r.local)b='<button class="btn s" onclick="applyUpd(this,true)" title="Скачает этот же выпуск с GitHub заново и прогонит установщик — как обычное обновление, только на ту же версию. Лечение узла: если файлы, юниты или кроны разъехались, переустановка вернёт всё по местам. Доступы, ключи и рабочий канал сохранятся.">Переустановить '+esc(r.latest)+' принудительно</button> ';
    b+='<button class="btn s" onclick="toggleAuto()">'+(r.auto?'Выключить':'Включить')+' автообновление</button>';
    act.innerHTML=b}
  const wasBusy=window.__UPDBUSY;window.__UPDBUSY=busy;
  if(!busy&&wasBusy){ /* обновление только что закончилось — показать итог */
    if(live.phase==='done'){toast('Узел обновлён до '+esc(live.to||r.local||'')+' ✓','ok');await loadStatus()}
    else if(live.phase==='failed'){toast('Обновление не прошло: '+esc(live.why||'')+(live.rolled_back?' — откат выполнен, узел на прежней версии':' — откат не подтвердился!'),live.rolled_back?'warn':'bad')}}
  if(busy&&!window.__UPDPOLL){window.__UPDPOLL=1;
    setTimeout(async()=>{window.__UPDPOLL=0;try{await loadUpd()}catch(_){}},3000)}}
async function checkUpd(btn){await openFold('upd');if(btn)btn.disabled=true;toast('Спрашиваю GitHub, какая версия последняя…');
  try{const r=await api('/api/update/check',{method:'POST'});
    if(!r.ok){toast('Проверка не отработала: '+((r.output||'').split('\\n').pop()||'см. журнал узла'),'bad')}
    else toast(r.last_error?('Проверка не удалась: '+r.last_error)
         :(r.newer?('Доступна версия '+r.latest+' (у узла '+(r.local||'?')+')'):'Обновлений нет — стоит последняя версия'),
      r.last_error?'bad':(r.newer?'warn':'ok'));
    await loadUpd()}
  catch(e){toast('проверка обновлений: '+e.message,'bad')}
  finally{if(btn)btn.disabled=false}}
async function applyUpd(btn,force){const r0=window.__UPD||{};
  const q=force?('Принудительно переустановить версию '+(r0.latest||'?')+'?\\n\\nУзел скачает этот же выпуск с GitHub заново и прогонит установщик — как обычное обновление, только на ту же версию. Это лечение: разъехавшиеся файлы, юниты и кроны вернутся по местам. Доступы устройств, ключи, пароль панели и рабочий канал сохранятся; панель на несколько секунд перезапустится. Если что-то главное не поднимется — узел сам откатится.')
             :('Обновить узел до версии '+(r0.latest||'?')+' прямо сейчас?\\n\\nУзел скачает выпуск с GitHub и переустановит сам себя тем же установщиком: доступы устройств, ключи, пароль панели и рабочий канал сохранятся. Панель на несколько секунд перезапустится. Если что-то главное не поднимется — узел сам откатится на текущую версию.');
  if(!confirm(q))return;
  if(btn)btn.disabled=true;toast(force?'Запускаю принудительную переустановку…':'Запускаю обновление…');
  try{const r=await api('/api/update/apply',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({force:!!force})});
    toast((force?'Переустановка ':'Обновление до ')+(r.started||'')+' запущена. Карточка покажет ход по шагам; панель может на минуту перестать отвечать — это нормально.','warn');
    window.__UPDBUSY=1;await loadUpd()}
  catch(e){toast('обновление: '+e.message,'bad');if(btn)btn.disabled=false}}
async function toggleAuto(){const r0=window.__UPD||{};const to=!r0.auto;
  if(!confirm(to?('Включить автообновление?\\n\\nУзел будет сам ставить новые версии ночью (окно '+(r0.window||'04:00-06:00')+' по времени сервера), с проверкой после установки и автооткатом при провале.')
               :'Выключить автообновление?\\n\\nУзел будет только сообщать о новых версиях (письмо и эта карточка), а обновлять придётся вручную.'))return;
  try{await api('/api/update/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({auto:to})});
    toast(to?'Автообновление включено':'Автообновление выключено — узел будет только сообщать о новинках','ok');
    await loadUpd()}
  catch(e){toast('настройка: '+e.message,'bad')}}

async function reloadAll(){try{for(const id of FOLD_ORDER)await loadFold(id)}
  catch(e){toast(e.message,'bad')}}

function ago(ts){if(!ts)return '<span class="mut">ещё ни разу</span>';const d=Math.floor(Date.now()/1000)-ts;
  if(d<0)return '<span class="ok">только что</span>';
  if(d<180)return '<span class="ok">на связи ('+d+' с назад)</span>';
  if(d<5400)return Math.floor(d/60)+' мин назад';
  if(d<172800)return Math.floor(d/3600)+' ч назад';return Math.floor(d/86400)+' дн назад'}
function fbytes(n){n=n||0;if(n<1024)return n+' Б';if(n<1048576)return (n/1024).toFixed(0)+' КБ';
  if(n<1073741824)return (n/1048576).toFixed(1)+' МБ';return (n/1073741824).toFixed(2)+' ГБ'}

async function loadClients(){const r=await api('/api/clients');const tb=document.querySelector('#clients tbody');tb.innerHTML='';
  for(const c of r.clients){const tr=document.createElement('tr');const nm=esc(c.name);
    tr.innerHTML='<td>'+nm+'</td><td>'+esc(c.ip)+'</td><td class="mut">'+ago(c.handshake)+'</td>'+
      '<td class="mut">'+fbytes(c.rx)+' / '+fbytes(c.tx)+'</td>'+
      '<td>'+(c.has_conf?('<button class="btn s tiny" onclick="dlClient(\\''+nm+'\\')" title="Файл для компьютера">Скачать</button> '+
        '<button class="btn s tiny" onclick="qrClient(\\''+nm+'\\')" title="Картинка для телефона">QR</button> '):
        '<span class="mut" title="профиль заведён мимо панели — файла с ключом нет">файла нет</span> ')+
      '<button class="btn r tiny" onclick="delClient(\\''+nm+'\\')">Отозвать</button></td>';
    tb.appendChild(tr)}
  window.__CN=r.clients.length;
  sum('clients','устройств: '+r.clients.length);
  document.getElementById('qstart').style.display=r.clients.length?'none':'grid';
  if(!r.clients.length)tb.innerHTML='<tr><td colspan="5" class="mut">доступ пока никому не выдан — начни с шагов выше</td></tr>';
  if(window.__S)beacon(window.__S,window.__CN)}

async function addClient(){const n=document.getElementById('cname').value.trim();if(!n)return toast('впиши имя устройства','bad');
  await openFold('clients');
  toast('Создаю профиль '+n+'…');try{const r=await api('/api/clients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})});
    document.getElementById('cname').value='';
    toast('Готово: '+r.name+' ('+r.ip+'). Дальше — «QR» для телефона или «Скачать» для компьютера.','ok');await loadClients()}catch(e){toast(e.message,'bad')}}

async function delClient(n){if(!confirm('Отозвать доступ у «'+n+'»?\\n\\nУстройство сразу потеряет VPN, его профиль удалится. Вернуть — только выдать новый.'))return;
  toast('Отзываю доступ '+n+'…');try{await api('/api/clients/'+encodeURIComponent(n)+'/delete',{method:'POST'});
    toast('Доступ «'+n+'» отозван','ok');await loadClients()}catch(e){toast(e.message,'bad')}}

function dlClient(n){window.location='/api/clients/'+encodeURIComponent(n)+'/config'}

async function qrClient(n){try{const r=await fetch('/api/clients/'+encodeURIComponent(n)+'/qr',{headers:{'X-CSRF-Token':CSRF}});
  const svg=await r.text();if(!r.ok){toast('QR: '+svg,'bad');return}
  document.getElementById('qrimg').innerHTML=svg;
  document.getElementById('qrname').textContent='Профиль «'+n+'» — открой WireGuard на телефоне, нажми «+» → «Сканировать QR-код»';
  document.getElementById('qrpanel').style.display='block';document.getElementById('qrpanel').scrollIntoView({behavior:'smooth'})}catch(e){toast(e.message,'bad')}}

async function refresh(){toast('Спрашиваю у провайдера список прокси…');try{const r=await api('/api/pool/refresh',{method:'POST'});
  toast('Пул обновлён: '+JSON.stringify(r.providers),'ok');await reloadAll()}catch(e){toast(e.message,'bad')}}

async function egress(auto){window.__EGBUSY=1;
  if(window.__S)beacon(window.__S,window.__CN);
  if(!auto)toast('Проверяю, какой IP видят сайты…');
  try{const s=await api('/api/egress',{method:'POST'});
    toast('Сайты видят '+(s.egress||'—')+(s.egress_cc?(' ('+country(s.egress_cc)+')'):'')+
      ', Telegram отвечает кодом '+s.tg_code+' → '+(s.ok?'всё в порядке':'цепочка нарушена'+(s.why?(': '+s.why):'')),
      s.ok?'ok':'bad')}
  catch(e){toast('проверка выхода: '+e.message,'bad')}
  finally{window.__EGBUSY=0;await loadStatus()}}

async function probe(btn,uid){btn.disabled=true;toast('Проверяю '+uid+'…');try{const r=await api('/api/proxy/'+encodeURIComponent(uid)+'/probe',{method:'POST'});
  toast(uid+': '+(r.ok?'годен, оценка '+r.score:'не прошёл ('+(r.disqualified||'')+')')+', выход '+(r.exit_ip||'—')+
    (r.exit_cc?(' из '+country(r.exit_cc)):''),r.ok?'ok':'bad');await loadPool()}catch(e){toast(e.message,'bad')}btn.disabled=false}

async function apply(btn,uid){if(!confirm('Сделать '+uid+' боевым?\\n\\nПорядок: проверка прокси → переключение сервера → повторная проверка. '+
    'Если после переключения станет хуже, панель вернёт прежний прокси сама. Клиенты в этот момент могут на пару секунд потерять связь.'))return;
  btn.disabled=true;toast('Переключаю на '+uid+'…');
  try{const r=await api('/api/proxy/'+encodeURIComponent(uid)+'/apply',{method:'POST'});
    toast('Готово: было '+r.old_ip+', стало '+r.new_ip+'. Сайты теперь видят '+r.egress+' ('+country(r.egress_cc)+')','ok');await reloadAll()}
  catch(e){toast('переключение: '+e.message,'bad');await reloadAll()}btn.disabled=false}

async function rollback(){if(!confirm('Вернуть предыдущий конфиг из резервной копии?\\n\\nПригодится, если после смены прокси стало хуже.'))return;toast('Откатываю…');
  try{const r=await api('/api/rollback',{method:'POST'});toast('Откат: '+r.bad_ip+' → '+r.good_ip+' → '+(r.ok?'связь восстановлена':'проверка не прошла'),r.ok?'ok':'bad');await reloadAll()}catch(e){toast(e.message,'bad')}}

async function setRole(sel){try{await api('/api/proxy/'+encodeURIComponent(sel.dataset.uid)+'/role',
  {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:sel.value})});
  toast('Роль '+sel.dataset.uid+' → '+sel.value,'ok');await loadPool()}catch(e){toast(e.message,'bad');await loadPool()}}

async function doRotate(){if(!confirm('Запустить автоматическую починку?\\n\\nПанель проверит текущий прокси и по порядку попробует: '+
    'подстроить настройки → переключиться на живой из пула → докупить новый (если разрешено лимитами) → включить аварийный режим. '+
    'Может сменить прокси и потратить деньги.'))return;
  toast('Запускаю диагностику и починку в фоне…');
  try{const r=await api('/api/rotate',{method:'POST'});
    if(r.state!==undefined){ /* dev-режим: агент отработал синхронно */
      toast('Итог: '+r.state+(r.output?('\\n'+r.output):''),r.state=='OK'?'ok':(r.state=='EMERGENCY'?'bad':'warn'));
      await reloadAll();return}
    if(r.busy)toast('Ротация уже идёт — жду её итог','warn');
    /* F6: ротация идёт транзиентным юнитом — поллим статус до завершения */
    let s=null;
    for(let n=0;n<200;n++){await new Promise(res=>setTimeout(res,3000));
      try{s=await api('/api/status');window.__S=s;if(!s.rotate_busy)break}catch(e){}}
    const st=(s&&s.automat)||'?';
    toast('Итог починки: '+st,st=='OK'?'ok':(st=='EMERGENCY'?'bad':'warn'));
    await reloadAll()}
  catch(e){toast('починка: '+e.message,'bad');await reloadAll()}}

async function doEmergency(){let cur=false;try{cur=(await api('/api/status')).emergency}catch(e){}
  const on=!cur;
  if(!confirm(on?'Включить аварийный режим?\\n\\nКлиенты получат интернет напрямую через сервер: связь будет, но выход — с российского IP, '+
    'то есть без обхода блокировок. Зато трафик не будет утекать в мёртвый туннель.'
    :'Выключить аварийный режим и вернуть трафик на зарубежный прокси?'))return;
  toast(on?'Включаю аварийный режим…':'Возвращаю трафик на прокси…');
  try{const r=await api('/api/emergency',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({on:on})});
    toast('Аварийный режим: '+(r.on?'ВКЛЮЧЁН':'выключен')+' (состояние '+r.state+')',r.on?'bad':'ok');await reloadAll()}
  catch(e){toast('авария: '+e.message,'bad')}}

reloadAll();setInterval(loadStatus,30000);
</script>
"""


def dashboard_page(server_name, csrf):
    body = _fill(_DASH_HTML, SRV=_esc(server_name), CSRF=_esc(csrf), CSRFJS=_js(csrf),
                 MAPCOLS=str(_MAP_COLS), MAPROWS=str(_MAP_ROWS),
                 MAPL0=repr(_MAP_BOX[0]), MAPL1=repr(_MAP_BOX[1]),
                 MAPB0=repr(_MAP_BOX[2]), MAPB1=repr(_MAP_BOX[3]),
                 MAPCC=_js(_MAP_CC), MAPLAND=_js(_MAP_LAND))
    return _doc("vpn-panel — %s" % _esc(server_name), body)


# ─────────────────────────── мастер первого входа ───────────────────────
_SETUP_HTML = """
<div class="wrap" style="max-width:620px">
  <div class="brand">VPN&nbsp;PANEL<small>первичная настройка · 5 шагов<span class="cursor"></span></small></div>

  <div class="ex danger" style="margin-top:12px">⚠️ <b>Сейчас панель никем не занята и открыта любому,
    кто знает адрес.</b> Пройди настройку до конца прямо сейчас — на последнем шаге вход закроется паролем
    и одноразовым кодом.</div>

  <div class="ex">Что вообще происходит: ты только что поднял свой VPN-сервер. Эта настройка задаёт
    <b>пароль</b> для входа сюда, включает <b>второй фактор</b> (чтобы одного пароля было мало),
    подключает <b>кабинет провайдера прокси</b> (чтобы панель могла сама покупать и менять зарубежные
    адреса выхода) и почту для писем об авариях. Каждый шаг объясню на месте.</div>

  <div class="sub" id="stepper" style="margin:14px 0"></div>

  <div class="card" id="s1">
    <h2>Шаг 1 · Пароль от панели</h2>
    <div class="ex">Этим паролем ты будешь заходить в эту панель. <b>Лучше нажать «Сгенерировать»</b> —
      получится длинный случайный пароль, его сразу сохрани в менеджер паролей или запиши.
      Пароль хранится на сервере только в виде математического отпечатка: подсмотреть его потом
      нельзя даже с правами root.</div>
    <button class="btn g" onclick="genPw()">Сгенерировать надёжный</button>
    <div id="pwout" class="msg" style="display:none"></div>
    <label>…или придумать свой (минимум 8 символов)</label>
    <input id="pwown" type="text" autocomplete="off" placeholder="минимум 8 символов">
    <button class="btn s" style="margin-top:9px" onclick="setPw()">Задать свой</button>
    <div style="margin-top:16px"><button class="btn" id="n1" disabled onclick="go(2)">Дальше →</button></div>
  </div>

  <div class="card" id="s2" style="display:none">
    <h2>Шаг 2 · Второй фактор (одноразовые коды)</h2>
    <div class="ex">Второй фактор — это приложение на телефоне, которое каждые 30 секунд показывает новый
      6-значный код. Даже если пароль украдут, без телефона не войдут.<br>
      <b>Что делать:</b> установи <b>Google Authenticator</b>, <b>Aegis</b> или <b>1Password</b> →
      нажми «Показать QR-код» → в приложении «+» → «Сканировать QR-код» → введи сюда появившийся код.<br>
      <b>Recovery-коды</b> после подтверждения — это запасные ключи на случай потери телефона.
      Сохрани их отдельно от телефона: без них и без приложения вход будет закрыт.</div>
    <button class="btn" onclick="totpNew()">Показать QR-код</button>
    <div id="qrbox" class="qrwrap" style="margin:13px 0;display:none"></div>
    <div id="secbox" class="sub" style="word-break:break-all"></div>
    <label>Код из приложения</label><input id="otp" autocomplete="off" inputmode="numeric" placeholder="6 цифр">
    <button class="btn g" style="margin-top:9px" onclick="totpVerify()">Подтвердить</button>
    <div id="recbox" class="msg" style="display:none"></div>
    <div style="margin-top:16px"><button class="btn s" onclick="go(1)">← Назад</button>
      <button class="btn" id="n2" disabled onclick="go(3)">Дальше →</button></div>
  </div>

  <div class="card" id="s3" style="display:none">
    <h2>Шаг 3 · Кабинет провайдера прокси</h2>
    <div class="ex">Твой сервер выпускает трафик наружу не сам, а через <b>арендованный зарубежный
      прокси</b> — именно его IP видят сайты. Прокси иногда умирают или блокируются. Чтобы панель могла
      сама купить и подставить новый, ей нужен ключ доступа к твоему кабинету у провайдера.<br>
      <b>Где взять:</b> зайди в личный кабинет провайдера → раздел «API» → скопируй ключ.<br>
      <b>PROXY6 — основной</b>: у него панель умеет покупать, продлевать и удалять, цены в рублях.
      Учти: <b>удаление денег не возвращает</b> (проверено живым экспериментом), поэтому оплаченный
      прокси выгоднее додержать до конца срока. Ключ проверяется сразу — панель покажет твой баланс.<br>
      <b>Нужен хотя бы один рабочий ключ</b> — без него мастер не завершится. Если сервис недоступен с сервера
      напрямую (у российских хостеров так бывает с PROXY6), ключ сохранится без проверки рядом с рабочим:
      узел будет ходить к такому сервису через собственный канал.</div>
    <label>PROXY6 · API-ключ (рекомендуется)</label><input id="proxy6" autocomplete="off" placeholder="например 0000000000-…">
    <label>ProxyLine · API-ключ (необязательно)</label><input id="proxyline" autocomplete="off">
    <button class="btn g" style="margin-top:9px" onclick="saveProv()">Проверить и сохранить</button>
    <div id="provbox" class="sub" style="margin-top:9px"></div>
    <div style="margin-top:16px"><button class="btn s" onclick="go(2)">← Назад</button>
      <button class="btn" id="n3" disabled onclick="go(4)">Дальше →</button></div>
  </div>

  <div class="card" id="s4" style="display:none">
    <h2>Шаг 4 · Почта для тревожных писем</h2>
    <div class="ex">Куда писать, если VPN сломался, прокси умер или деньги на исходе. Нужны данные
      почтового ящика, от имени которого слать письма (те же, что вбиваются в почтовый клиент:
      сервер, порт, логин, пароль). Письма приходят с адреса логина — отдельно его указывать не нужно.
      Заполни и нажми <b>«Проверить связь»</b>: узел отправит на этот ящик код, впиши его обратно —
      только так почта включится, чтобы «сохранено» не означало «письма молча не ходят».
      <b>Не знаешь — жми «Пропустить»</b>, панель будет работать без писем, настроишь потом.</div>
    <label>Почтовый сервер (SMTP)</label><input id="sm_host" autocomplete="off" placeholder="mail.example.com">
    <div class="field">
      <div style="flex:1;min-width:90px"><label>порт</label><input id="sm_port" placeholder="587"></div>
      <div style="flex:2;min-width:160px"><label>логин</label><input id="sm_user" autocomplete="off"></div>
    </div>
    <label>пароль от ящика</label><input id="sm_password" type="password" autocomplete="new-password">
    <div id="sm_from_row" style="display:none">
      <label>адрес отправителя</label><input id="sm_from" autocomplete="off" placeholder="vpn@example.com">
      <div class="sub">Логин не похож на почтовый адрес — впишите, с какого адреса слать письма.</div>
    </div>
    <label>кому слать</label><input id="sm_to" autocomplete="off" placeholder="you@example.com">
    <div style="margin-top:11px"><button class="btn g" onclick="testSmtp()">Проверить связь</button>
      <button class="btn s" onclick="skipSmtp()">Пропустить</button></div>
    <div id="sm_code_row" style="display:none;margin-top:11px">
      <label>код из письма</label><input id="sm_code" autocomplete="off" placeholder="6 цифр">
      <button class="btn g" style="margin-top:9px" onclick="saveSmtp()">Подтвердить и включить почту</button>
    </div>
    <div id="smtpbox" class="sub" style="margin-top:9px"></div>
    <div style="margin-top:16px"><button class="btn s" onclick="go(3)">← Назад</button>
      <button class="btn" id="n4" disabled onclick="go(5)">Дальше →</button></div>
  </div>

  <div class="card" id="s5" style="display:none">
    <h2>Шаг 5 · Завершение</h2>
    <div class="ex">Нажми «Завершить» — панель закроется паролем и вторым фактором, откроется обычный вход.
      Дальше первым делом выдай себе доступ на телефон: раздел «Кто подключён» → имя устройства →
      «Выдать доступ» → «QR».</div>
    <div class="ex danger">Проверь, что <b>пароль и recovery-коды сохранены</b> — второй раз они не покажутся.</div>
    <button class="btn g" onclick="finish()">Завершить настройку</button>
  </div>

  <div class="foot">соединение защищено самоподписанным сертификатом — предупреждение браузера здесь ожидаемо</div>
</div>
<div id="toast"></div>
"""

_SETUP_JS = """
function esc(s){return (s==null?'':''+s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function toast(t,cls){const d=document.createElement('div');d.className='msg '+(cls||'');d.textContent=t;
  document.getElementById('toast').appendChild(d);setTimeout(()=>d.remove(),9000)}
async function sapi(path,obj){const r=await fetch(path,{method:'POST',
  headers:{'X-Setup-Token':SETUP,'Content-Type':'application/json'},body:JSON.stringify(obj||{})});
  const t=await r.text();let j;try{j=JSON.parse(t)}catch(e){j={error:t}}
  if(!r.ok){const err=new Error(j.error||('HTTP '+r.status));Object.assign(err,j);throw err}
  return j}
let CUR=1;const DONE={};
const NAMES=['','пароль','второй фактор','провайдер','почта','готово'];
function stepper(){document.getElementById('stepper').innerHTML=
  [1,2,3,4,5].map(i=>'<span class="pill'+(DONE[i]?' ok':'')+'" style="margin-right:6px'+
   (i==CUR?';border-color:var(--cyan);color:var(--cyan)':'')+'">'+i+(DONE[i]?' ✓':'')+'</span>').join('')+
   ' <span class="mut">'+NAMES[CUR]+'</span>'}
function go(n){for(let i=1;i<=5;i++)document.getElementById('s'+i).style.display=(i==n?'block':'none');
  CUR=n;stepper();window.scrollTo({top:0,behavior:'smooth'})}
function done(n){DONE[n]=true;const b=document.getElementById('n'+n);if(b)b.disabled=false;stepper()}
async function genPw(){try{const r=await sapi('/api/setup/password',{});const o=document.getElementById('pwout');
  o.style.display='block';o.className='msg ok';
  o.textContent='Твой пароль (сохрани прямо сейчас!):\\n'+r.password;done(1)}catch(e){toast(e.message,'bad')}}
async function setPw(){const p=document.getElementById('pwown').value;if(p.length<8)return toast('нужно минимум 8 символов','bad');
  try{await sapi('/api/setup/password',{password:p});const o=document.getElementById('pwout');
  o.style.display='block';o.className='msg ok';o.textContent='Пароль сохранён.';done(1)}catch(e){toast(e.message,'bad')}}
async function totpNew(){try{const r=await sapi('/api/setup/totp/new',{});
  const box=document.getElementById('qrbox');box.style.display='inline-block';box.innerHTML=r.qr;
  document.getElementById('secbox').textContent='Если камера не берёт QR — введи ключ вручную: '+r.secret}catch(e){toast(e.message,'bad')}}
async function totpVerify(){const c=document.getElementById('otp').value;
  try{const r=await sapi('/api/setup/totp/verify',{code:c});const o=document.getElementById('recbox');
  o.style.display='block';o.className='msg ok';
  o.textContent='Второй фактор подключён. Запасные recovery-коды (сохрани отдельно от телефона):\\n'+r.recovery.join('  ');
  done(2)}catch(e){toast(e.message,'bad')}}
async function saveProv(){const b={proxy6:document.getElementById('proxy6').value.trim(),
  proxyline:document.getElementById('proxyline').value.trim()};
  try{const r=await sapi('/api/setup/provider',b);const box=document.getElementById('provbox');
  box.innerHTML=Object.entries(r.result||{}).map(([k,v])=>k+': '+(v.ok?('<span class="ok">ключ рабочий, баланс '+v.balance+' '+(v.currency||'')+'</span>'):
    v.saved_unverified?('<span class="warn">сервис недоступен с сервера напрямую — ключ сохранён без проверки, узел будет ходить к нему через свой канал ('+esc(v.error)+')</span>'):
    ('<span class="bad">'+esc(v.error)+'</span>'))).join('<br>');
  done(3)}catch(e){document.getElementById('provbox').innerHTML='<span class="bad">'+esc(e.message)+'</span>';toast(e.message,'bad')}}
const SM_FIELDS=['sm_host','sm_port','sm_user','sm_password','sm_from','sm_to'];
function smBody(){return {host:v('sm_host'),port:v('sm_port'),user:v('sm_user'),
  password:v('sm_password'),from:v('sm_from'),to:v('sm_to')}}
function smBox(cls,txt){document.getElementById('smtpbox').innerHTML='<span class="'+cls+'">'+esc(txt)+'</span>'}
// правку полей после отправки кода прячем обратно за проверку: сохраняем только проверенное
function smReset(){document.getElementById('sm_code_row').style.display='none'}
async function testSmtp(){const b=smBody();smBox('mut','отправляю письмо с кодом…');
  try{const r=await sapi('/api/setup/smtp/test',b);
    document.getElementById('sm_code_row').style.display='block';
    document.getElementById('sm_code').focus();
    smBox('ok','письмо с кодом отправлено на '+r.to+' — впиши код из письма (идёт до пары минут)')}
  catch(e){if(e.need_from)document.getElementById('sm_from_row').style.display='block';
    smBox('bad',e.message);toast(e.message,'bad')}}
async function saveSmtp(){const b=smBody();b.code=v('sm_code');
  try{await sapi('/api/setup/smtp',b);smBox('ok','почта проверена и включена');done(4)}
  catch(e){if(e.need_test)smReset();if(e.need_from)document.getElementById('sm_from_row').style.display='block';
    smBox('bad',e.message);toast(e.message,'bad')}}
async function skipSmtp(){try{await sapi('/api/setup/smtp',{skip:true});
  document.getElementById('smtpbox').innerHTML='<span class="mut">почта пропущена — настроишь позже</span>';done(4)}catch(e){toast(e.message,'bad')}}
function v(id){return document.getElementById(id).value.trim()}
async function finish(){try{const r=await sapi('/api/setup/finish',{});toast('Готово! Открываю вход…','ok');
  setTimeout(()=>location.href=r.next||'/login',1200)}catch(e){toast(e.message,'bad')}}
SM_FIELDS.forEach(function(id){var el=document.getElementById(id);
  if(el)el.addEventListener('input',smReset)});
stepper();
"""


def setup_page(setup_csrf):
    body = _SETUP_HTML + "<script>const SETUP=" + _js(setup_csrf) + ";\n" + _SETUP_JS + "</script>"
    return _doc("Настройка — vpn-panel", body)


# ─────────────────────────── каркас документа ───────────────────────────
def _doc(title, body):
    return ("<!doctype html><html lang=ru><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><style>%s</style></head><body>%s</body></html>"
            % (_esc(title), _BASE_CSS, body))


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _js(s):
    import json
    return json.dumps(s)
