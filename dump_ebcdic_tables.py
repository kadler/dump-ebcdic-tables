from ctypes import c_char, c_int, c_uint, c_int16, c_uint16, \
                   c_size_t, c_ulonglong, c_void_p, c_char_p, \
                   addressof, sizeof, create_string_buffer, \
                   CDLL, DEFAULT_MODE, POINTER, Structure

import unicodedata

RTLD_MEMBER = 0x00040000


class ILEPointer(Structure):
    "An ILE pointer type"
    _pack_ = 16
    _fields_ = [
        ("hi", c_ulonglong),
        ("lo", c_ulonglong)
    ]

    def __str__(self):
        return f"{self.hi:016x}{self.lo:016x}"


try:
    _LIBC = CDLL("/QOpenSys/usr/lib/libc.a(shr_64.o)",
                 DEFAULT_MODE | RTLD_MEMBER)

    _SETSPP = _LIBC._SETSPP
    _SETSPP.argtypes = [POINTER(ILEPointer), c_void_p]

    _ILELOADX = _LIBC._ILELOADX
    _ILELOADX.argtypes = [c_char_p, c_uint]
    _ILELOADX.restype = c_ulonglong

    _ILESYMX = _LIBC._ILESYMX
    _ILESYMX.argtypes = [POINTER(ILEPointer), c_ulonglong, c_char_p]

    _ILECALLX = _LIBC._ILECALLX
    _ILECALLX.argtypes = [
        POINTER(ILEPointer),
        c_void_p,
        POINTER(c_int16),
        c_int16,
        c_int
    ]

    _RSLOBJ = _LIBC._RSLOBJ
    _RSLOBJ.argtypes = [
        POINTER(ILEPointer),
        c_char_p,
        c_char_p
    ]

    _RSLOBJ2 = _LIBC._RSLOBJ2
    _RSLOBJ2.argtypes = [
        POINTER(ILEPointer),
        c_uint16,
        c_char_p,
        c_char_p
    ]

    _PGMCALL = _LIBC._PGMCALL
    _PGMCALL.argtypes = [
        POINTER(ILEPointer),
        c_void_p,
        c_uint,
    ]

    _CVTSPP = _LIBC._CVTSPP
    _CVTSPP.argtypes = [POINTER(ILEPointer)]
    _CVTSPP.restype = c_void_p

    _MEMCPY_WT2 = _LIBC._MEMCPY_WT2
    _MEMCPY_WT2.argtypes = [
        POINTER(ILEPointer),
        POINTER(ILEPointer),
        c_size_t,
    ]

except OSError:
    # Either we couldn't load libc or we couldn't find the necessary syscalls
    # exported from libc. Either way, this platform is unsupported so we raise
    # an import error to prevent it from being used.
    raise ImportError

ILELOAD_LIBOBJ = 0x00000001
ILESYM_PROCEDURE = 1

ILECALL_NOINTERRUPT = 0x00000004
ILECALL_EXCP_NOSIGNAL = 0x00000020

RSLOBJ_TS_PGM = 0x0201
RSLOBJ_TS_SRVPGM = 0x0203

PGMCALL_DIRECT_ARGS = 0x00000001
PGMCALL_DROP_ADOPT = 0x00000002
PGMCALL_NOINTERRUPT = 0x00000004
PGMCALL_NOMAXARGS = 0x00000008
PGMCALL_ASCII_STRINGS = 0x00000010
PGMCALL_EXCP_NOSIGNAL = 0x00000020

RESULT_VOID = 0
RESULT_INT8 = -1
RESULT_UINT8 = -2
RESULT_INT16 = -3
RESULT_UINT16 = -4
RESULT_INT32 = -5
RESULT_UINT32 = -6
RESULT_INT64 = -7
RESULT_UINT64 = -8
RESULT_FLOAT64 = -10
RESULT_FLOAT128 = -18

ARG_END = 0
ARG_MEMPTR = -11


class MemPointer(ILEPointer):
    "An ILE pointer type to be used with ARG_MEMPTR"
    _pack_ = 16

    def __init__(self, addr=0):
        super().__int__()
        self.hi = 0
        self.lo = addr

    @property
    def addr(self):
        return self.lo

    @addr.setter
    def addr(self, addr):
        self.lo = addr


class ILEArglistBase(Structure):
    "ILECALL argument list base member"
    _pack_ = 16
    _fields_ = [
        ('descriptor', ILEPointer),
        ('result', ILEPointer),
    ]


class qtqcode_t(Structure):
    "An ILE pointer type"
    _pack_ = 16
    _fields_ = [
        ("ccsid", c_int),
        ("conversion_alternative", c_int),
        ("substitution_alternative", c_int),
        ("shift_state_alternative", c_int),
        ("input_length_option", c_int),
        ("mixed_data_error_option", c_int),
        ("_reserved", c_char * 8),
    ]

    def __str__(self):
        out_fields = [
            f"{getattr(self, _[0])}"
            for _ in self._fields_
            if not _[0][0] == '_'
         ]
        return " ".join(out_fields)


class iconv_t(Structure):
    "An ILE pointer type"
    _pack_ = 16
    _fields_ = [
        ("rtn", c_int),
        ("cd", c_int * 12)
    ]

    def __str__(self):
        return " ".join([f"{_:x}" for _ in self.cd])


class IconvOpenArglist(Structure):
    "Argument list definition for the RUNASCII procedure"
    _pack_ = 16
    _fields_ = [
        ('base', ILEArglistBase),
        ('to_code', MemPointer),
        ('from_code', MemPointer),
    ]


class IconvCloseArglist(Structure):
    "Argument list definition for the RUNASCII procedure"
    _pack_ = 16
    _fields_ = [
        ('base', ILEArglistBase),
        ('cd', iconv_t),
    ]


class IconvArglist(Structure):
    "Argument list definition for the RUNASCII procedure"
    # _pack_ = 16
    _fields_ = [
        ('base', ILEArglistBase),
        ('cd', iconv_t),
        ('pad', c_char * 12),
        ('in_buf', MemPointer),
        ('in_len', MemPointer),
        ('out_buf', MemPointer),
        ('out_len', MemPointer),
    ]


def load_symbol(library, srvpgm, symbol):
    obj = f"{library}/{srvpgm}"

    actgrp = _ILELOADX(obj.encode(), ILELOAD_LIBOBJ)
    if actgrp == 0xffffffffffffffff:
        raise OSError(f"{obj} not found")

    ptr = ILEPointer()
    if _ILESYMX(ptr, actgrp, symbol.encode()) != ILESYM_PROCEDURE:
        raise OSError(f"{symbol} procedure not found in {obj}")

    return ptr


# actgrp = _ILELOADX(b"QSYS/QC2UTIL1", ILELOAD_LIBOBJ)
# if actgrp == 0xffffffffffffffff:
#     raise OSError("QC2UTIL1 not found")

# errno_ptr = ILEPointer()
# if _ILESYMX(errno_ptr, actgrp, b'__errno') != ILESYM_PROCEDURE:
#     raise OSError(f"__errno procedure not found in QC2UTIL1")


# actgrp = _ILELOADX(b"QSYS/QTQICONV", ILELOAD_LIBOBJ)
# if actgrp == 0xffffffffffffffff:
#     raise OSError("QTQICONV not found")

# for sym in ['QtqIconvOpen', 'iconv_open', 'iconv_close', 'iconv']:
#     ptr = ILEPointer()
#     if _ILESYMX(ptr, actgrp, sym.encode()) != ILESYM_PROCEDURE:
#         raise OSError(f"{sym} procedure not found in QTQICONV")
#     globals()[f"{sym}_ptr"] = ptr

# qtqgesp_ptr = ILEPointer()
# if _RSLOBJ2(qtqgesp_ptr, RSLOBJ_TS_PGM, b"QTQGESP", b"QSYS"):
#     raise OSError("Error resolving program")


def get_ile_errno():
    try:
        ptr = get_ile_errno.ptr
    except AttributeError:
        ptr = get_ile_errno.ptr = load_symbol("QSYS", "QC2UTIL1", "__errno")

    errnop = ILEPointer()

    arglist = ILEArglistBase()
    arglist.result.lo = addressof(errnop)

    signature = c_int16(ARG_END)

    if _ILECALLX(ptr, addressof(arglist), signature, 16, ILECALL_EXCP_NOSIGNAL):
        raise RuntimeError("Failed to call QtqIconvOpen with _ILECALL")

    errno_buf = create_string_buffer(4)
    errnop_pase = ILEPointer()
    _SETSPP(errnop_pase, errno_buf)
    _MEMCPY_WT2(errnop_pase, errnop, 4)

    return int(errno_buf.raw.hex(), 16)


def iconv_open(out_ccsid, in_ccsid):
    try:
        ptr = iconv_open.ptr
    except AttributeError:
        ptr = iconv_open.ptr = load_symbol("QSYS", "QTQICONV", "QtqIconvOpen")

    to_code = qtqcode_t(out_ccsid)
    from_code = qtqcode_t(
        in_ccsid,
        0,  # 0=default conversion, 57=enforced subset match, 102=best fit
        0,  # don't return the number of substitution characters
        0,  # don't reset the shift state at the start of iconv()
        0,  # iconv() does not call strlen() on the input
        0,  # iconv() doesn't error on DBCS in mixed
    )

    cd = iconv_t()

    arglist = IconvOpenArglist()
    arglist.to_code.addr = addressof(to_code)
    arglist.from_code.addr = addressof(from_code)
    arglist.base.result.lo = addressof(cd)

    signature = (c_int16 * 3)(
            ARG_MEMPTR,
            ARG_MEMPTR,
            ARG_END
    )

    if _ILECALLX(ptr, addressof(arglist), signature, sizeof(cd),
                 ILECALL_EXCP_NOSIGNAL):
        raise RuntimeError("Failed to call QtqIconvOpen with _ILECALL")

    return cd


def iconv_close(cd):
    try:
        ptr = iconv_close.ptr
    except AttributeError:
        ptr = iconv_close.ptr = load_symbol("QSYS", "QTQICONV", "iconv_close")

    arglist = IconvCloseArglist()
    arglist.cd = cd

    signature = (c_int16 * 2)(
        sizeof(cd),
        ARG_END
    )

    if _ILECALLX(ptr, addressof(arglist), signature, RESULT_INT32, ILECALL_EXCP_NOSIGNAL):
        raise RuntimeError("Failed to call iconv_close with _ILECALL")

    return arglist.base.result.hi


def iconv(cd, data):
    try:
        ptr = iconv.ptr
    except AttributeError:
        ptr = iconv.ptr = load_symbol("QSYS", "QTQICONV", "iconv")

    in_len = c_uint(len(data))
    in_buf = create_string_buffer(data)
    in_ptr = ILEPointer()

    _SETSPP(in_ptr, addressof(in_buf))

    out_len = c_uint(8)
    out_buf = create_string_buffer(out_len.value)
    out_ptr = ILEPointer()
    _SETSPP(out_ptr, addressof(out_buf))

    arglist = IconvArglist()
    arglist.cd = cd
    arglist.in_buf.addr = addressof(in_ptr)
    arglist.in_len.addr = addressof(in_len)
    arglist.out_buf.addr = addressof(out_ptr)
    arglist.out_len.addr = addressof(out_len)

    signature = (c_int16 * 6)(
        sizeof(cd),
        ARG_MEMPTR,
        ARG_MEMPTR,
        ARG_MEMPTR,
        ARG_MEMPTR,
        ARG_END
    )

    if _ILECALLX(ptr, addressof(arglist), signature, RESULT_UINT32, 0):
        raise RuntimeError("Failed to call iconv with _ILECALL")

    out_size = len(out_buf) - out_len.value
    return arglist.base.result.hi, out_buf.raw[:out_size]


def get_encoding_scheme(ccsid):
    try:
        ptr = get_encoding_scheme.ptr
    except AttributeError:
        ptr = ILEPointer()
        if _RSLOBJ2(ptr, RSLOBJ_TS_PGM, b"QTQGESP", b"QSYS"):
            raise OSError("Error resolving QTQGESP")
        get_encoding_scheme.ptr = ptr

    ccsid1 = c_int(ccsid)
    n1 = c_int(2)
    n2 = c_int(0)
    es = c_int()
    cspl = (c_int * 2)()
    fb = (c_int * 3)()

    args = (c_void_p * 7)(
        addressof(ccsid1),
        addressof(n1),
        addressof(n2),
        addressof(es),
        addressof(cspl),
        addressof(fb),
        0
    )
    if _PGMCALL(ptr, addressof(args), PGMCALL_EXCP_NOSIGNAL):
        raise OSError("_PGMCALL")

    if any(fb):
        return -1

    return es.value


def dump_conv_table(ccsid, es):
    cd = iconv_open(1200, ccsid)
    if cd.rtn == -1:
        print("Couldn't open converter")
        return

    if es == 0x1100:
        max_cp = 256
        cp_size = 1
    else:
        max_cp = 65536
        cp_size = 2

    table = [None] * max_cp
    for cp in range(max_cp):
        data = cp.to_bytes(cp_size, byteorder='big')
        rc, out = iconv(cd, data)

        table[cp] = out

    iconv_close(cd)

    return table


def write_conv_txt(table, file):
    if len(table) == 256:
        fmt_str = "0x{:02x}\t0x{}\t{}"
    else:
        fmt_str = "0x{:04x}\t0x{}\t{}"

    for cp, out in enumerate(table):
        try:
            u = out.decode('utf-16be')
            name = unicodedata.name(u)
        except ValueError:
            category = unicodedata.category(u)
            if category == 'Cc':
                name = '<control>'
            else:
                name = '<unknown>'
        except UnicodeDecodeError:
            name = '<error>'
            pass

        print(fmt_str.format(cp, out.hex(), name), file=file)


CONTROL_CODES = {
    '\u0000': 'NUL', '\u0001': 'SOH', '\u0002': 'STX', '\u0003': 'ETX',
    '\u0004': 'EOT', '\u0005': 'ENQ', '\u0006': 'ACK', '\u0007': 'BEL',
    '\u0008': 'BS',  '\u0009': 'HT',  '\u000a': 'LF',  '\u000b': 'VT',
    '\u000c': 'FF',  '\u000d': 'CR',  '\u000e': 'SO',  '\u000f': 'SI',
    '\u0010': 'DLE', '\u0011': 'DC1', '\u0012': 'DC2', '\u0013': 'DC3',
    '\u0014': 'DC4', '\u0015': 'NAK', '\u0016': 'SYN', '\u0017': 'ETB',
    '\u0018': 'CAN', '\u0019': 'EM',  '\u001a': 'SUB', '\u001b': 'ESC',
    '\u001c': 'FS',  '\u001d': 'GS',  '\u001e': 'RS',  '\u001f': 'US',
    '\u007f': 'DEL',


    '\u0080': 'PAD', '\u0081': 'HOP',  '\u0082': 'BPH', '\u0083': 'NBH',
    '\u0084': 'IND', '\u0085': 'NEL',  '\u0086': 'SSA', '\u0087': 'ESA',
    '\u0088': 'HTS', '\u0089': 'HTJ',  '\u008a': 'VTS', '\u008b': 'PLD',
    '\u008c': 'PLU', '\u008d': 'RI',   '\u008e': 'SS2', '\u008f': 'SS3',
    '\u0090': 'DCS', '\u0091': 'PU1',  '\u0092': 'PU2', '\u0093': 'STS',
    '\u0094': 'CCH', '\u0095': 'MW',   '\u0096': 'SPA', '\u0097': 'EPA',
    '\u0098': 'SOS', '\u0099': 'SGCI', '\u009a': 'SCI', '\u009b': 'CSI',
    '\u009c': 'ST',  '\u009d': 'OSC',  '\u009e': 'PM',  '\u009f': 'APC',
}

SPACE = {
    '\u0020': 'SP',
    '\u00a0': 'NBSP',
    '\u00ad': 'SHY',
    '\u202f': 'NNBSP',
    '\u205f': 'MMSP',
}

CATEGORY_CLASS = {
    'Cc': 'control-code',
    'Zs': 'space-separator',
    'Sc': 'symbol', 'Sk': 'symbol', 'Sm': 'symbol', 'So': 'symbol',
    'Pc': 'punctuation', 'Pd': 'punctuation', 'Pe': 'punctuation',
    'Pf': 'punctuation', 'Pi': 'punctuation', 'Po': 'punctuation',
    'Ps': 'punctuation',
    'Nd': 'number', 'Nl': 'number', 'No': 'number',
}


INVARIANTS = [
    chr(_)
    for _
    in list(range(0x41, 0x5b)) + list(range(0x61, 0x7b)) +
       list(range(0x30, 0x3a))
] + [
    "+", "<", "=", ">", "%",
    "&", "*", "\"", "'", "(",
    ")", ",", "_", "-", ".",
    "/", ":", ";", "?",
]


def write_conv_html(ccsid, table, file):
    if len(table) != 256:
        return
    html = f"""
<style>
#ebcdic-table {{
    text-align: center;
    font-size: large;
    border-collapse: collapse;
    color: black;
}}
th {{
    font-weight: 700;
    width: 3em;
    background-color: #EEEEEE;
}}
.th {{
    font-weight: 700;
    width: 1.6em;
    background-color: #EEEEEE;
}}
.row {{
    height: 4em;
}}
.glyph {{
    line-height: 1.6;
}}
.control-code {{
    font-variant: small-caps;
    font-family: monospace;
    background-color: #F0FFF0;
}}
.space-separator {{
    font-variant: small-caps;
    font-family: monospace;
    background-color: #F0FFF0;
}}
.symbol {{
    background-color: #FFFFD7;
}}
.punctuation {{
    background-color: #F4F4FF;
}}
.number {{
    background-color: #FFF4F4;
}}
.normal {{
    background-color: #FFFFFF;
}}
.invariant {{
    border: 2px solid;
}}
</style>
<table id="ebcdic-table" border="1" frame="box">
"""
    print(html, file=file)

    table_head = f"""
<tr>
    <th class='th'></th>
    <th>_0</th><th>_1</th><th>_2</th><th>_3</th>
    <th>_4</th><th>_5</th><th>_6</th><th>_7</th>
    <th>_8</th><th>_9</th><th>_A</th><th>_B</th>
    <th>_C</th><th>_D</th><th>_E</th><th>_F</th>
</tr>
"""
    print(table_head, file=file)

    for i in range(0, 16):
        print("<tr class='row'>", file=file)

        for j in range(0, 17):
            if j == 0:
                print(f"<td class='th'>_{i:X}</td>", end=None, file=file)
                continue
            j -= 1

            cp = i * 16 + j
            out = table[cp]

            u = out.decode('utf-16be')

            category = unicodedata.category(u)
            if u == '\ufffd':
                x = ''
            elif category == 'Cc':
                n = CONTROL_CODES.get(u, '')
                x = f"<span class='glyph'>{n}</span>"
            elif category == 'Zs':
                n = SPACE.get(u, '')
                x = f"<span class='glyph'>{n}</span>"
            else:
                x = f"<span class='glyph'>{u}</span>"
            x += f"<br><small>{ord(u):04X}</small>"

            cls = CATEGORY_CLASS.get(category, "normal")

            if u in INVARIANTS:
                cls += ' invariant'

            print(f"<td class=\"{cls}\">{x}</td>", end=None, file=file)
        print("\n</tr>", file=file)

    print(table_head, file=file)

    html = f"""
</table>
"""
    print(html, file=file)


for ccsid in range(1, 65535):
    es = get_encoding_scheme(ccsid)
    if es not in (0x1100, 0x1200):
        continue
    if ccsid in (16684, 57777):
        # TODO: Need to handle multi-unicode character conversions
        continue
    print(f"ccsid: {ccsid} {es:x}")
    table = dump_conv_table(ccsid, es)
    with open(f'IBM-{ccsid:03d}.txt', 'w') as conv_file:
        write_conv_txt(table, conv_file)
    if es != 0x1200:
        # TODO: Add support for generating DBCS html tables
        with open(f'IBM-{ccsid:03d}.html', 'w') as conv_file:
            write_conv_html(ccsid, table, conv_file)
