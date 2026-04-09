class TextRepairSupport:
    def __init__(self, *, re_module):
        self.re_module = re_module

    def fix_mojibake_text(self, value: str | None) -> str:
        text = value or ""
        if not text:
            return ""

        def _score(candidate: str) -> int:
            cyr = sum(1 for ch in candidate if "\u0400" <= ch <= "\u04FF")
            bad = len(self.re_module.findall(r"[\u00D0\u00D1\u0420\u0421\u0440\u0441](?=[^\s])", candidate))
            bad += len(self.re_module.findall(r"[\u201A\u201E\u2026\u2020\u2021\u2030\u2122]", candidate))
            bad += candidate.count("\uFFFD")
            return cyr * 2 - bad

        best = text
        best_score = _score(text)
        current = text

        for _ in range(3):
            candidates: list[str] = []
            try:
                candidates.append(current.encode("cp1251").decode("utf-8"))
            except Exception:
                pass
            try:
                candidates.append(current.encode("latin1").decode("utf-8"))
            except Exception:
                pass

            improved = False
            for candidate in candidates:
                score = _score(candidate)
                if score > best_score:
                    best = candidate
                    best_score = score
                    improved = True
            if not improved:
                break
            current = best

        return best
