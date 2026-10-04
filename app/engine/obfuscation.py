import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class ObfuscationResult:
    has_obfuscation: bool = False
    indicators: List[str] = field(default_factory=list)
    decoded_payloads: List[str] = field(default_factory=list)
    canonical_text: str = ""
    obfuscation_score: float = 0.0


class ObfuscationDetector:
    """Layer 3: Obfuscation & Evasion Detection and Payload Decoders."""

    # Cyrillic and Greek homoglyphs commonly used to evade Latin ASCII regexes
    HOMOGLYPH_MAP = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
        'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
        'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
        'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'Υ': 'Y', 'Ζ': 'Z',
    }

    # Leetspeak substitution map
    LEET_MAP = {
        '0': 'o',
        '1': 'i',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '@': 'a',
        '$': 's',
        '!': 'i',
    }

    BASE64_PATTERN = re.compile(r"\b([A-Za-z0-9+/]{16,}={0,2})\b")
    HEX_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]{2}[\s,]*){4,}|(?:[0-9a-fA-F]{2}[\s:-]){6,}[0-9a-fA-F]{2}")
    BINARY_PATTERN = re.compile(r"\b([01]{8}[\s]*){4,}\b")
    SPACED_LETTERS_PATTERN = re.compile(r"(?:[a-zA-Z][\s_\-\.]{1,2}){4,}[a-zA-Z]")

    def inspect(self, text: str) -> ObfuscationResult:
        indicators = []
        decoded_payloads = []
        penalty = 0.0

        # 1. Base64 Detection & Decoding
        b64_matches = self.BASE64_PATTERN.findall(text)
        for match in b64_matches:
            decoded = self._try_decode_base64(match)
            if decoded:
                indicators.append(f"Base64 encoded payload detected ({len(match)} chars)")
                decoded_payloads.append(decoded)
                penalty += 0.35

        # 2. Hexadecimal Detection & Decoding
        hex_matches = self.HEX_PATTERN.findall(text)
        for match in hex_matches:
            decoded = self._try_decode_hex(match)
            if decoded:
                indicators.append("Hexadecimal encoded sequence detected")
                decoded_payloads.append(decoded)
                penalty += 0.35

        # 3. Binary Detection & Decoding
        bin_matches = self.BINARY_PATTERN.findall(text)
        for match in bin_matches:
            decoded = self._try_decode_binary(match)
            if decoded:
                indicators.append("Binary byte stream payload detected")
                decoded_payloads.append(decoded)
                penalty += 0.35

        # 4. Spaced/Separated Letter Evasion (e.g. i-g-n-o-r-e or i g n o r e)
        if self.SPACED_LETTERS_PATTERN.search(text):
            despaced = self._despace_text(text)
            indicators.append("Character spacing / punctuation separator evasion detected")
            decoded_payloads.append(despaced)
            penalty += 0.30

        # 5. Unicode Homoglyph Normalization
        has_homoglyph = False
        homoglyph_clean = []
        for ch in text:
            if ch in self.HOMOGLYPH_MAP:
                homoglyph_clean.append(self.HOMOGLYPH_MAP[ch])
                has_homoglyph = True
            else:
                homoglyph_clean.append(ch)
        
        homoglyph_normalized = "".join(homoglyph_clean)
        if has_homoglyph:
            indicators.append("Unicode homoglyph / mixed-script characters detected")
            decoded_payloads.append(homoglyph_normalized)
            penalty += 0.25

        # 6. Leetspeak Normalization
        leet_normalized = self._normalize_leetspeak(text)
        if leet_normalized != text:
            # Only count as indicator if leet text reveals meaningful keyword
            if any(k in leet_normalized.lower() for k in ["ignore", "system", "override", "prompt", "bypass", "jailbreak"]):
                indicators.append("Adversarial Leetspeak character substitution detected")
                decoded_payloads.append(leet_normalized)
                penalty += 0.30

        # 7. Reversed text detection
        reversed_candidate = text[::-1]
        if any(k in reversed_candidate.lower() for k in ["ignore previous", "system prompt", "developer mode"]):
            indicators.append("Reversed string evasion detected")
            decoded_payloads.append(reversed_candidate)
            penalty += 0.35

        # Aggregate canonical search text for downstream layers
        combined_canonical = " ".join([text] + decoded_payloads)

        return ObfuscationResult(
            has_obfuscation=len(indicators) > 0,
            indicators=indicators,
            decoded_payloads=decoded_payloads,
            canonical_text=combined_canonical,
            obfuscation_score=min(1.0, penalty)
        )

    def _try_decode_base64(self, s: str) -> Optional[str]:
        try:
            # Pad base64 if needed
            pad_len = len(s) % 4
            if pad_len != 0:
                s += "=" * (4 - pad_len)
            raw_bytes = base64.b64decode(s, validate=True)
            decoded = raw_bytes.decode('utf-8', errors='ignore')
            # Check if decoded looks like readable text (at least 70% ascii printable)
            if len(decoded) >= 4 and sum(c.isprintable() for c in decoded) / len(decoded) >= 0.70:
                return decoded
        except Exception:
            pass
        return None

    def _try_decode_hex(self, s: str) -> Optional[str]:
        clean_hex = re.sub(r"[^0-9a-fA-F]", "", s)
        if len(clean_hex) >= 8 and len(clean_hex) % 2 == 0:
            try:
                raw_bytes = binascii.unhexlify(clean_hex)
                decoded = raw_bytes.decode('utf-8', errors='ignore')
                if len(decoded) >= 4 and sum(c.isprintable() for c in decoded) / len(decoded) >= 0.70:
                    return decoded
            except Exception:
                pass
        return None

    def _try_decode_binary(self, s: str) -> Optional[str]:
        clean_bin = re.sub(r"[^01]", "", s)
        if len(clean_bin) >= 32 and len(clean_bin) % 8 == 0:
            try:
                chars = [chr(int(clean_bin[i:i+8], 2)) for i in range(0, len(clean_bin), 8)]
                decoded = "".join(chars)
                if len(decoded) >= 4 and sum(c.isprintable() for c in decoded) / len(decoded) >= 0.70:
                    return decoded
            except Exception:
                pass
        return None

    def _despace_text(self, s: str) -> str:
        # 1. Remove hyphens/underscores/dots between single letters (e.g. i-g-n-o-r-e -> ignore)
        res = re.sub(r'([a-zA-Z])[\-_](?=[a-zA-Z])', r'\1', s)
        # 2. Despace single characters separated by single space (e.g. i g n o r e -> ignore)
        res = re.sub(r'(?<=\b[a-zA-Z])\s(?=[a-zA-Z]\b)', '', res)
        # 3. If letters were conjoined, ensure known command keywords have boundary spacing
        res = re.sub(r'(?i)(ignore|previous|prior|system|prompt|instructions|disregard|override|reveal|jailbreak)', r' \1 ', res)
        return re.sub(r'\s+', ' ', res).strip()

    def _normalize_leetspeak(self, s: str) -> str:
        chars = [self.LEET_MAP.get(c, c) for c in s]
        return "".join(chars)
