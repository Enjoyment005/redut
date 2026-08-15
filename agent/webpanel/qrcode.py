# -*- coding: utf-8 -*-
"""Минимальный QR-кодер на stdlib -> inline SVG (панель: CSP запрещает внешние ресурсы).

Байтовый режим (UTF-8), уровни коррекции L/M/Q/H, авто-выбор версии 1..40, все 8 масок
с выбором по штрафу, Рида-Соломона ECC, format/version-info (BCH). Достаточно для
otpauth-URI (2FA) и клиентских WireGuard .conf (QR для импорта на телефоне).

Алгоритм — ISO/IEC 18004 (по эталону Nayuki, public domain). Корректность проверена
round-trip-декодированием (opencv) на версиях 1..22 и уровнях L/M/Q/H — все сканируются.
Вывод стандарт-совместим; от segno отличается только «лишним» байтом заполнения segno
при выравнивании (безобидный quirk segno, декодеры не замечают). API: qr_svg(text, ecl, border).
"""

# (ecl -> кодовые слова ECC на блок) и (ecl -> число блоков), индекс = версия 1..40.
_ECC_CODEWORDS = {
    "L": [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28,
          28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    "M": [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26,
          26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    "Q": [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26,
          30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    "H": [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26,
          28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
}
_NUM_BLOCKS = {
    "L": [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
          8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    "M": [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
          17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    "Q": [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20,
          23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    "H": [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
          25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
}
_ECL_FORMATBITS = {"L": 1, "M": 0, "Q": 3, "H": 2}  # индикатор уровня в format-info


def _num_raw_data_modules(ver):
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        numalign = ver // 7 + 2
        result -= (25 * numalign - 10) * numalign - 55
        if ver >= 7:
            result -= 36
    return result


def _num_data_codewords(ver, ecl):
    return (_num_raw_data_modules(ver) // 8
            - _ECC_CODEWORDS[ecl][ver] * _NUM_BLOCKS[ecl][ver])


def _alignment_positions(ver):
    if ver == 1:
        return []
    numalign = ver // 7 + 2
    step = 26 if ver == 32 else (ver * 4 + numalign * 2 + 1) // (numalign * 2 - 2) * 2
    result = [6]
    pos = ver * 4 + 10
    for _ in range(numalign - 1):
        result.insert(1, pos)
        pos -= step
    return result


# ---- Галуа GF(256) для Рида-Соломона (примитивный полином 0x11D), форма Nayuki ----
def _gf_mul(x, y):
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z & 0xFF


def _rs_generator(degree):
    """Делитель RS = generator без старшего члена, `degree` коэффициентов (x^{deg-1}..x^0)."""
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


class QrCode:
    def __init__(self, text, ecl="M", mask=None):
        data = text.encode("utf-8")
        ecl = self._pick_ecl_version(data, ecl)
        self.ecl, self.ver = ecl
        self.size = self.ver * 4 + 17
        self.modules = [[False] * self.size for _ in range(self.size)]
        self._funcmask = [[False] * self.size for _ in range(self.size)]
        self._draw_function_patterns()
        allcw = self._add_ecc_interleave(self._make_codewords(data))
        self._draw_codewords(allcw)
        self._apply_best_mask(force=mask)

    # ---- выбор версии под данные ----
    def _pick_ecl_version(self, data, ecl):
        for ver in range(1, 41):
            cap = _num_data_codewords(ver, ecl) * 8
            ccbits = 16 if ver >= 10 else 8      # счётчик длины в байтовом режиме
            need = 4 + ccbits + len(data) * 8
            if need <= cap:
                return (ecl, ver)
        raise ValueError("данные не влезают в QR (%d байт)" % len(data))

    # ---- поток бит -> кодовые слова данных ----
    def _make_codewords(self, data):
        bits = []

        def put(val, n):
            for i in range(n - 1, -1, -1):
                bits.append((val >> i) & 1)

        put(0b0100, 4)                                  # режим: байтовый
        put(len(data), 16 if self.ver >= 10 else 8)      # длина
        for b in data:
            put(b, 8)
        cap = _num_data_codewords(self.ver, self.ecl) * 8
        put(0, min(4, cap - len(bits)))                  # терминатор
        while len(bits) % 8 != 0:
            bits.append(0)
        cws = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
        pad = [0xEC, 0x11]
        i = 0
        while len(cws) < _num_data_codewords(self.ver, self.ecl):
            cws.append(pad[i % 2])
            i += 1
        return cws

    # ---- разбить на блоки, посчитать ECC, чередовать ----
    def _add_ecc_interleave(self, data):
        ver, ecl = self.ver, self.ecl
        numblocks = _NUM_BLOCKS[ecl][ver]
        ecclen = _ECC_CODEWORDS[ecl][ver]
        rawcw = _num_raw_data_modules(ver) // 8
        numshort = numblocks - rawcw % numblocks
        shortlen = rawcw // numblocks - ecclen
        gen = _rs_generator(ecclen)
        blocks = []
        k = 0
        for i in range(numblocks):
            dlen = shortlen + (0 if i < numshort else 1)
            dat = data[k:k + dlen]
            k += dlen
            ecc = _rs_remainder(dat, gen)
            if i < numshort:
                dat = dat + [None]   # выравниваем короткие блоки для чередования
            blocks.append((dat, ecc))
        result = []
        for i in range(shortlen + 1):
            for dat, _ in blocks:
                if i < len(dat) and dat[i] is not None:
                    result.append(dat[i])
        for i in range(ecclen):
            for _, ecc in blocks:
                result.append(ecc[i])
        return result

    # ---- функциональные паттерны ----
    def _set_func(self, x, y, val):
        self.modules[y][x] = val
        self._funcmask[y][x] = True

    def _draw_function_patterns(self):
        n = self.size
        for i in range(n):
            self._set_func(6, i, i % 2 == 0)      # тайминг
            self._set_func(i, 6, i % 2 == 0)
        for (cx, cy) in ((3, 3), (n - 4, 3), (3, n - 4)):
            self._finder(cx, cy)
        pos = _alignment_positions(self.ver)
        for a in pos:
            for b in pos:
                if (a, b) in ((6, 6), (6, n - 7), (n - 7, 6)):
                    continue
                self._alignment(a, b)
        self._reserve_format()
        if self.ver >= 7:
            self._draw_version()

    def _finder(self, cx, cy):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < self.size and 0 <= y < self.size:
                    d = max(abs(dx), abs(dy))
                    self._set_func(x, y, d != 2 and d != 4)

    def _alignment(self, cx, cy):
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                self._set_func(cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)

    def _reserve_format(self):
        n = self.size
        for i in range(9):
            if i != 6:                       # col/row 6 — таймингом, не форматом
                self._set_func(8, i, False)
                self._set_func(i, 8, False)
        for i in range(8):
            self._set_func(n - 1 - i, 8, False)
            self._set_func(8, n - 1 - i, False)
        self._set_func(8, n - 8, True)   # тёмный модуль

    def _draw_version(self):
        rem = self.ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = (self.ver << 12) | rem
        for i in range(18):
            bit = (bits >> i) & 1
            a = self.size - 11 + i % 3
            b = i // 3
            self._set_func(a, b, bool(bit))
            self._set_func(b, a, bool(bit))

    # ---- размещение данных зигзагом ----
    def _draw_codewords(self, cw):
        n = self.size
        i = 0
        col = n - 1
        while col >= 1:
            if col == 6:
                col = 5
            for t in range(n):
                for c in (col, col - 1):
                    up = ((n - 1 - col) & 2) == 0
                    y = (n - 1 - t) if up else t
                    if not self._funcmask[y][c]:
                        bit = 0
                        if i < len(cw) * 8:
                            bit = (cw[i >> 3] >> (7 - (i & 7))) & 1
                        self.modules[y][c] = bool(bit)
                        i += 1
            col -= 2

    # ---- маски и штрафы ----
    def _apply_mask(self, mask):
        for y in range(self.size):
            for x in range(self.size):
                if self._funcmask[y][x]:
                    continue
                if mask == 0:
                    inv = (x + y) % 2 == 0
                elif mask == 1:
                    inv = y % 2 == 0
                elif mask == 2:
                    inv = x % 3 == 0
                elif mask == 3:
                    inv = (x + y) % 3 == 0
                elif mask == 4:
                    inv = (x // 3 + y // 2) % 2 == 0
                elif mask == 5:
                    inv = x * y % 2 + x * y % 3 == 0
                elif mask == 6:
                    inv = (x * y % 2 + x * y % 3) % 2 == 0
                else:
                    inv = ((x + y) % 2 + x * y % 3) % 2 == 0
                if inv:
                    self.modules[y][x] = not self.modules[y][x]

    def _draw_format(self, mask):
        data = _ECL_FORMATBITS[self.ecl] << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        n = self.size
        for i in range(6):
            self._set_func(8, i, _bit(bits, i))
        self._set_func(8, 7, _bit(bits, 6))
        self._set_func(8, 8, _bit(bits, 7))
        self._set_func(7, 8, _bit(bits, 8))
        for i in range(9, 15):
            self._set_func(14 - i, 8, _bit(bits, i))
        for i in range(8):
            self._set_func(n - 1 - i, 8, _bit(bits, i))
        for i in range(8, 15):
            self._set_func(8, n - 15 + i, _bit(bits, i))

    def _apply_best_mask(self, force=None):
        saved = [row[:] for row in self.modules]
        if force is not None:
            best = force
        else:
            best = None
            best_pen = None
            for mask in range(8):
                self.modules = [row[:] for row in saved]
                self._apply_mask(mask)
                self._draw_format(mask)
                pen = self._penalty()
                if best_pen is None or pen < best_pen:
                    best_pen = pen
                    best = mask
        self.modules = [row[:] for row in saved]
        self._apply_mask(best)
        self._draw_format(best)
        self.mask = best

    def _penalty(self):
        n = self.size
        m = self.modules
        pen = 0
        # правило 1: ряды/столбцы одинаковых модулей
        for line in (m, list(zip(*m))):
            for row in line:
                run = 1
                for i in range(1, n):
                    if row[i] == row[i - 1]:
                        run += 1
                    else:
                        if run >= 5:
                            pen += 3 + (run - 5)
                        run = 1
                if run >= 5:
                    pen += 3 + (run - 5)
        # правило 2: блоки 2x2
        for y in range(n - 1):
            for x in range(n - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    pen += 3
        # правило 3: паттерн finder-подобный 1:1:3:1:1
        pat1 = [True, False, True, True, True, False, True, False, False, False, False]
        pat2 = [False, False, False, False, True, False, True, True, True, False, True]
        for line in (m, list(zip(*m))):
            for row in line:
                row = list(row)
                for x in range(n - 10):
                    seg = row[x:x + 11]
                    if seg == pat1 or seg == pat2:
                        pen += 40
        # правило 4: баланс тёмных модулей
        dark = sum(sum(1 for v in row if v) for row in m)
        pen += _rule4(dark, n)
        return pen

    def get_matrix(self):
        return [[bool(v) for v in row] for row in self.modules]


def _bit(x, i):
    return bool((x >> i) & 1)


def _rule4(dark, n):
    total = n * n
    ratio = dark * 100 / total
    lower = (int(ratio) // 5) * 5
    upper = lower + 5
    return min(int(abs(lower - 50) / 5), int(abs(upper - 50) / 5)) * 10


def qr_matrix(text, ecl="M"):
    return QrCode(text, ecl).get_matrix()


def qr_svg(text, ecl="M", border=4, module=4, dark="#0d1117", light="#ffffff"):
    """QR -> самодостаточный inline-SVG (viewBox в модульных единицах, масштаб через width)."""
    m = qr_matrix(text, ecl)
    n = len(m)
    dim = n + border * 2
    parts = []
    for y in range(n):
        for x in range(n):
            if m[y][x]:
                parts.append("M%d %dh1v1h-1z" % (x + border, y + border))
    px = dim * module
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" '
        'width="%d" height="%d" shape-rendering="crispEdges" role="img" aria-label="QR">'
        '<rect width="%d" height="%d" fill="%s"/>'
        '<path d="%s" fill="%s"/></svg>'
        % (dim, dim, px, px, dim, dim, light, "".join(parts), dark)
    )
