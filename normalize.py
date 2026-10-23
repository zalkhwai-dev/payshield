"""
Undo the tricks scammers use to slip past keyword filters, while remembering
where every character came from, so we can still highlight the ORIGINAL text.

Handles:
  P@yPal, paypa1, $end        -> leetspeak / symbol swaps
  pаypal (Cyrillic 'а')        -> look-alike letters from other alphabets
  u.r.g.e.n.t / u r g e n t    -> letters split with dots, dashes or spaces
  ur🔥gent, pay​pal (zero-width) -> emojis / invisible characters inside words
  عـــاجل, عَاجِل                 -> Arabic tatweel and diacritics
  أ إ آ ى ة                     -> Arabic letter variants folded together
"""

import re
import unicodedata

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­", "‎", "‏"}
TATWEEL = "ـ"
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "Α": "a", "Β": "b", "Ε": "e", "Ο": "o", "Ρ": "p",
    "ο": "o", "ν": "v", "α": "a",
})
LEET = {"@": "a", "$": "s", "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "!": "i", "|": "l"}
ARABIC_FOLD = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي", "ة": "ه", "ؤ": "و", "ئ": "ي"})


def fold_arabic(text: str) -> str:
    """Fold Arabic letter variants. Also used on the rule patterns themselves."""
    return text.translate(ARABIC_FOLD)


def _is_diacritic(ch: str) -> bool:
    return "ً" <= ch <= "ٟ" or ch == "ٰ"


def _is_emoji(ch: str) -> bool:
    return unicodedata.category(ch) in {"So", "Sk"} or 0x1F000 <= ord(ch) <= 0x1FAFF or 0x2600 <= ord(ch) <= 0x27BF


def normalize(text: str):
    """Return (normalized_text, index_map) where index_map[i] = position in the original text."""
    chars, imap = [], []

    # pass 1: per-character cleanup
    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH or ch == TATWEEL or _is_diacritic(ch) or ch == "️":
            continue
        if _is_emoji(ch):
            chars.append("\x00")  # placeholder, decided in pass 2
            imap.append(i)
            continue
        ch = unicodedata.normalize("NFKC", ch)[:1] or ch
        chars.append(ch.translate(HOMOGLYPHS).lower())
        imap.append(i)

    # pass 2: emoji inside a word -> remove; elsewhere -> space
    out, omap = [], []
    for k, ch in enumerate(chars):
        if ch == "\x00":
            prev = next((c for c in reversed(chars[:k]) if c != "\x00"), " ")
            nxt = next((c for c in chars[k + 1:] if c != "\x00"), " ")
            if prev.isalpha() and nxt.isalpha():
                continue
            ch = " "
        out.append(ch)
        omap.append(imap[k])

    # pass 3: leetspeak inside Latin words (only when the token has real letters)
    s = "".join(out)
    res, rmap = list(s), list(omap)
    for m in re.finditer(r"[A-Za-z0-9@$!|]+", s):
        token = m.group(0)
        letters = sum(c.isalpha() for c in token)
        if letters >= 2 and letters < len(token) and not token.isdigit():
            # trailing punctuation like "urgent!!" stays punctuation
            stop = m.end()
            while stop > m.start() and s[stop - 1] in "!|":
                stop -= 1
            for j in range(m.start(), stop):
                res[j] = LEET.get(res[j], res[j])
    s = "".join(res)

    # pass 4: re-join letters split by separators: u.r.g.e.n.t / p-a-y-p-a-l / u r g e n t
    pattern = re.compile(r"(?<![^\W\d_])(?:[^\W\d_][\s.\-_*·•]){3,}[^\W\d_](?![^\W\d_])")
    final, fmap, pos = [], [], 0
    for m in pattern.finditer(s):
        final.extend(s[pos:m.start()]); fmap.extend(rmap[pos:m.start()])
        for j in range(m.start(), m.end()):
            if s[j].isalpha():
                final.append(s[j]); fmap.append(rmap[j])
        pos = m.end()
    final.extend(s[pos:]); fmap.extend(rmap[pos:])

    return fold_arabic("".join(final)), fmap


def to_original_span(start: int, end: int, imap: list[int]) -> tuple[int, int]:
    return imap[start], imap[end - 1] + 1


def detect_tricks(text: str) -> list[str]:
    """Which disguise tricks appear in the text? Using them is itself a red flag."""
    found = []
    if any(c in ZERO_WIDTH for c in text):
        found.append("invisible characters")
    if re.search(r"[A-Za-z][аеорсухіјѕԁοα]|[аеорсухіјѕԁοα][A-Za-z]", text):
        found.append("look-alike letters from another alphabet")
    if re.search(r"\b[A-Za-z]{2,}[@$01][A-Za-z]{1,}\b|\b[@$][A-Za-z]{3,}\b", text):
        found.append("symbol/number swaps (e.g. P@yPal)")
    if re.search(r"(?<![^\W\d_])(?:[^\W\d_][.\-_*·•]){3,}[^\W\d_](?![^\W\d_])", text):
        found.append("letters split with dots or dashes")
    if re.search(r"[A-Za-z][\U0001F000-\U0001FAFF☀-➿][A-Za-z]", text):
        found.append("emojis inside words")
    return found
