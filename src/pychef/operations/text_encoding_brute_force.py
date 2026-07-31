"""Enumerate CyberChef's text code pages using Python's built-in codecs."""

from __future__ import annotations

import codecs
import json
from functools import cache

from ..registry import operation
from ..types import Args, Data, to_text
from ._utils import arg

_CODE_PAGES = (
    ("UTF-8 (65001)", 65001),
    ("UTF-7 (65000)", 65000),
    ("UTF-16LE (1200)", 1200),
    ("UTF-16BE (1201)", 1201),
    ("UTF-32LE (12000)", 12000),
    ("UTF-32BE (12001)", 12001),
    ("IBM EBCDIC International (500)", 500),
    ("IBM EBCDIC US-Canada (37)", 37),
    ("IBM EBCDIC Multilingual/ROECE (Latin 2) (870)", 870),
    ("IBM EBCDIC Greek Modern (875)", 875),
    ("IBM EBCDIC French (1010)", 1010),
    ("IBM EBCDIC Turkish (Latin 5) (1026)", 1026),
    ("IBM EBCDIC Latin 1/Open System (1047)", 1047),
    ("IBM EBCDIC Lao (1132/1133/1341)", 1132),
    ("IBM EBCDIC US-Canada (037 + Euro symbol) (1140)", 1140),
    ("IBM EBCDIC Germany (20273 + Euro symbol) (1141)", 1141),
    ("IBM EBCDIC Denmark-Norway (20277 + Euro symbol) (1142)", 1142),
    ("IBM EBCDIC Finland-Sweden (20278 + Euro symbol) (1143)", 1143),
    ("IBM EBCDIC Italy (20280 + Euro symbol) (1144)", 1144),
    ("IBM EBCDIC Latin America-Spain (20284 + Euro symbol) (1145)", 1145),
    ("IBM EBCDIC United Kingdom (20285 + Euro symbol) (1146)", 1146),
    ("IBM EBCDIC France (20297 + Euro symbol) (1147)", 1147),
    ("IBM EBCDIC International (500 + Euro symbol) (1148)", 1148),
    ("IBM EBCDIC Icelandic (20871 + Euro symbol) (1149)", 1149),
    ("IBM EBCDIC Germany (20273)", 20273),
    ("IBM EBCDIC Denmark-Norway (20277)", 20277),
    ("IBM EBCDIC Finland-Sweden (20278)", 20278),
    ("IBM EBCDIC Italy (20280)", 20280),
    ("IBM EBCDIC Latin America-Spain (20284)", 20284),
    ("IBM EBCDIC United Kingdom (20285)", 20285),
    ("IBM EBCDIC Japanese Katakana Extended (20290)", 20290),
    ("IBM EBCDIC France (20297)", 20297),
    ("IBM EBCDIC Arabic (20420)", 20420),
    ("IBM EBCDIC Greek (20423)", 20423),
    ("IBM EBCDIC Hebrew (20424)", 20424),
    ("IBM EBCDIC Korean Extended (20833)", 20833),
    ("IBM EBCDIC Thai (20838)", 20838),
    ("IBM EBCDIC Icelandic (20871)", 20871),
    ("IBM EBCDIC Cyrillic Russian (20880)", 20880),
    ("IBM EBCDIC Turkish (20905)", 20905),
    ("IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) (20924)", 20924),
    ("IBM EBCDIC Cyrillic Serbian-Bulgarian (21025)", 21025),
    ("OEM United States (437)", 437),
    ("OEM Greek (formerly 437G); Greek (DOS) (737)", 737),
    ("OEM Baltic; Baltic (DOS) (775)", 775),
    ("OEM Russian; Cyrillic + Euro symbol (808)", 808),
    ("OEM Multilingual Latin 1; Western European (DOS) (850)", 850),
    ("OEM Latin 2; Central European (DOS) (852)", 852),
    ("OEM Cyrillic (primarily Russian) (855)", 855),
    ("OEM Turkish; Turkish (DOS) (857)", 857),
    ("OEM Multilingual Latin 1 + Euro symbol (858)", 858),
    ("OEM Portuguese; Portuguese (DOS) (860)", 860),
    ("OEM Icelandic; Icelandic (DOS) (861)", 861),
    ("OEM Hebrew; Hebrew (DOS) (862)", 862),
    ("OEM French Canadian; French Canadian (DOS) (863)", 863),
    ("OEM Arabic; Arabic (864) (864)", 864),
    ("OEM Nordic; Nordic (DOS) (865)", 865),
    ("OEM Russian; Cyrillic (DOS) (866)", 866),
    ("OEM Modern Greek; Greek, Modern (DOS) (869)", 869),
    ("OEM Cyrillic (primarily Russian) + Euro Symbol (872)", 872),
    ("Windows-874 Thai (874)", 874),
    ("Windows-1250 Central European (1250)", 1250),
    ("Windows-1251 Cyrillic (1251)", 1251),
    ("Windows-1252 Latin (1252)", 1252),
    ("Windows-1253 Greek (1253)", 1253),
    ("Windows-1254 Turkish (1254)", 1254),
    ("Windows-1255 Hebrew (1255)", 1255),
    ("Windows-1256 Arabic (1256)", 1256),
    ("Windows-1257 Baltic (1257)", 1257),
    ("Windows-1258 Vietnam (1258)", 1258),
    ("ISO-8859-1 Latin 1 Western European (28591)", 28591),
    ("ISO-8859-2 Latin 2 Central European (28592)", 28592),
    ("ISO-8859-3 Latin 3 South European (28593)", 28593),
    ("ISO-8859-4 Latin 4 North European (28594)", 28594),
    ("ISO-8859-5 Latin/Cyrillic (28595)", 28595),
    ("ISO-8859-6 Latin/Arabic (28596)", 28596),
    ("ISO-8859-7 Latin/Greek (28597)", 28597),
    ("ISO-8859-8 Latin/Hebrew (28598)", 28598),
    ("ISO 8859-8 Hebrew (ISO-Logical) (38598)", 38598),
    ("ISO-8859-9 Latin 5 Turkish (28599)", 28599),
    ("ISO-8859-10 Latin 6 Nordic (28600)", 28600),
    ("ISO-8859-11 Latin/Thai (28601)", 28601),
    ("ISO-8859-13 Latin 7 Baltic Rim (28603)", 28603),
    ("ISO-8859-14 Latin 8 Celtic (28604)", 28604),
    ("ISO-8859-15 Latin 9 (28605)", 28605),
    ("ISO-8859-16 Latin 10 (28606)", 28606),
    ("ISO 2022 JIS Japanese with no halfwidth Katakana (50220)", 50220),
    ("ISO 2022 JIS Japanese with halfwidth Katakana (50221)", 50221),
    ("ISO 2022 Japanese JIS X 0201-1989 (1 byte Kana-SO/SI) (50222)", 50222),
    ("ISO 2022 Korean (50225)", 50225),
    ("ISO 2022 Simplified Chinese (50227)", 50227),
    ("ISO 6937 Non-Spacing Accent (20269)", 20269),
    ("EUC Japanese (51932)", 51932),
    ("EUC Simplified Chinese (51936)", 51936),
    ("EUC Korean (51949)", 51949),
    ("ISCII Devanagari (57002)", 57002),
    ("ISCII Bengali (57003)", 57003),
    ("ISCII Tamil (57004)", 57004),
    ("ISCII Telugu (57005)", 57005),
    ("ISCII Assamese (57006)", 57006),
    ("ISCII Oriya (57007)", 57007),
    ("ISCII Kannada (57008)", 57008),
    ("ISCII Malayalam (57009)", 57009),
    ("ISCII Gujarati (57010)", 57010),
    ("ISCII Punjabi (57011)", 57011),
    ("Japanese Shift-JIS (932)", 932),
    ("Simplified Chinese GBK (936)", 936),
    ("Korean (949)", 949),
    ("Traditional Chinese Big5 (950)", 950),
    ("US-ASCII (7-bit) (20127)", 20127),
    ("Simplified Chinese GB2312 (20936)", 20936),
    ("KOI8-R Russian Cyrillic (20866)", 20866),
    ("KOI8-U Ukrainian Cyrillic (21866)", 21866),
    ("Mazovia (Polish) MS-DOS (620)", 620),
    ("Arabic (ASMO 708) (708)", 708),
    ("Arabic (Transparent ASMO); Arabic (DOS) (720)", 720),
    ("Kamenický (Czech) MS-DOS (895)", 895),
    ("Korean (Johab) (1361)", 1361),
    ("MAC Roman (10000)", 10000),
    ("Japanese (Mac) (10001)", 10001),
    ("MAC Traditional Chinese (Big5) (10002)", 10002),
    ("Korean (Mac) (10003)", 10003),
    ("Arabic (Mac) (10004)", 10004),
    ("Hebrew (Mac) (10005)", 10005),
    ("Greek (Mac) (10006)", 10006),
    ("Cyrillic (Mac) (10007)", 10007),
    ("MAC Simplified Chinese (GB 2312) (10008)", 10008),
    ("Romanian (Mac) (10010)", 10010),
    ("Ukrainian (Mac) (10017)", 10017),
    ("Thai (Mac) (10021)", 10021),
    ("MAC Latin 2 (Central European) (10029)", 10029),
    ("Icelandic (Mac) (10079)", 10079),
    ("Turkish (Mac) (10081)", 10081),
    ("Croatian (Mac) (10082)", 10082),
    ("CNS Taiwan (Chinese Traditional) (20000)", 20000),
    ("TCA Taiwan (20001)", 20001),
    ("ETEN Taiwan (Chinese Traditional) (20002)", 20002),
    ("IBM5550 Taiwan (20003)", 20003),
    ("TeleText Taiwan (20004)", 20004),
    ("Wang Taiwan (20005)", 20005),
    ("Western European IA5 (IRV International Alphabet 5) (20105)", 20105),
    ("IA5 German (7-bit) (20106)", 20106),
    ("IA5 Swedish (7-bit) (20107)", 20107),
    ("IA5 Norwegian (7-bit) (20108)", 20108),
    ("T.61 (20261)", 20261),
    ("Japanese (JIS 0208-1990 and 0212-1990) (20932)", 20932),
    ("Korean Wansung (20949)", 20949),
    ("Extended/Ext Alpha Lowercase (21027)", 21027),
    ("Europa 3 (29001)", 29001),
    ("Atari ST/TT (47451)", 47451),
    ("HZ-GB2312 Simplified Chinese (52936)", 52936),
    ("Simplified Chinese GB18030 (54936)", 54936),
)
_SPECIAL_CODECS = {
    65001: "utf-8",
    65000: "utf-7",
    1200: "utf-16le",
    1201: "utf-16be",
    12000: "utf-32le",
    12001: "utf-32be",
    20127: "ascii",
    50220: "iso2022_jp",
    50221: "iso2022_jp_ext",
    50222: "iso2022_jp",
    50225: "iso2022_kr",
    50227: "iso2022_jp_2",
    51932: "euc_jp",
    51936: "gb2312",
    51949: "euc_kr",
    932: "shift_jis",
    936: "gbk",
    949: "cp949",
    950: "big5",
    20936: "gb2312",
    20866: "koi8_r",
    21866: "koi8_u",
    10000: "mac_roman",
    10007: "mac_cyrillic",
    10029: "mac_latin2",
    10079: "mac_iceland",
    10081: "mac_turkish",
    10082: "mac_croatian",
    52936: "hz",
    54936: "gb18030",
}


@cache
def _codec_name(code_page: int) -> str | None:
    candidates = []
    if code_page in _SPECIAL_CODECS:
        candidates.append(_SPECIAL_CODECS[code_page])
    if 28591 <= code_page <= 28606:
        candidates.append(f"iso8859_{code_page - 28590}")
    candidates.append(f"cp{code_page}")
    for candidate in candidates:
        try:
            return codecs.lookup(candidate).name
        except LookupError:
            continue
    return None


@operation("Text Encoding Brute Force", category="Encodings")
def text_encoding_brute_force(value: Data, args: Args) -> Data:
    mode = str(arg(args, 0, "Encode"))
    text = to_text(value)
    output: dict[str, str] = {}
    for label, code_page in _CODE_PAGES:
        codec = _codec_name(code_page)
        if codec is None:
            output[label] = "Could not decode."
            continue
        try:
            if mode == "Decode":
                output[label] = text.encode("latin-1").decode(codec)
            else:
                output[label] = text.encode(codec).decode("utf-8")
        except (UnicodeError, ValueError):
            output[label] = "Could not decode."
    return json.dumps(output, ensure_ascii=False, indent=2)
