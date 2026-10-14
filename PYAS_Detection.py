"""Detection facts, separate from AI advice and compatible with legacy string labels.

Scores are supplied by the detector. YARA's fixed return value is a match flag,
never a calibrated malware probability. Unknown facts stay unknown.
"""
from dataclasses import asdict, dataclass
import math
import re

_LABEL = re.compile(r"(?P<category>[A-Za-z][A-Za-z0-9]*):(?P<platform>[A-Za-z0-9]+)/(?P<family>[^\r\n]+)\.(?P<number>[0-9]{1,3})!(?P<engine>ml|yr|ym|cl)\Z")
_ENGINES = frozenset(("ml", "yr", "ym", "cl"))


def _valid_score(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or not 0 <= value <= 100:
        return None
    return int(value) if value == int(value) else float(value)


@dataclass(frozen=True)
class DetectionEvidence:
    raw_label: str = ""
    engine: str = "unknown"
    status: str = "unknown"
    category: str = ""
    platform: str = ""
    family: str = ""
    generic: bool = False
    score: int | float | None = None
    score_kind: str = "not_provided"
    rules: tuple = ()
    rule_count: int | None = None
    description: str = ""
    schema_version: int = 1

    def view(self):
        data = asdict(self)
        data["rules"] = list(self.rules)
        return data


def _evidence(label, engine=None, score=None, description="", rules=(), legacy=False):
    label = str(label or "")
    match = _LABEL.fullmatch(label)
    category = match["category"] if match else ""
    platform = match["platform"] if match else ""
    family = match["family"] if match else ""
    engine = engine if engine in _ENGINES else (match["engine"] if match else "unknown")
    names = tuple(str(name)[:256] for name in rules)
    kind = "not_provided"
    value = None
    count = None
    if engine in ("yr", "ym"):
        kind = "rule_match"
        count = len(names) if names else (int(match["number"]) if match else None)
    elif engine in ("ml", "cl"):
        # Old persisted labels encode the detector score; arbitrary text is not a score.
        value = _valid_score(int(match["number"]) if legacy and match else score)
        if value is not None:
            kind = "model_probability" if engine == "ml" else "cloud_score"
    return DetectionEvidence(
        raw_label=label[:1024], engine=engine, status="detected" if label else "unknown",
        category=category, platform=platform, family=family, generic=family.lower() == "general",
        score=value, score_kind=kind, rules=names[:64], rule_count=count,
        description=str(description or "")[:1024],
    )


class DetectionResult(str):
    """A label still works with bool/str/JSON, carrying immutable per-scan facts.

    Facts travel with cache entries, not thread-local "last result" state.
    """
    def __new__(cls, label, evidence):
        obj = super().__new__(cls, label)
        obj._evidence = evidence
        return obj

    @property
    def evidence(self):
        return self._evidence

    def __getnewargs__(self):
        return str(self), self.evidence


def detection_result(label, engine, score=None, description="", rules=()):
    if not label:
        return False
    return DetectionResult(str(label), _evidence(label, engine, score, description, rules))


def detection_view(result, action="", description=""):
    if isinstance(result, DetectionResult):
        return result.evidence.view()
    if isinstance(result, str) and result:
        return _evidence(result, description=description, legacy=True).view()
    if action == "Network Block" and isinstance(result, dict) and result.get("remote_ip"):
        return DetectionEvidence(engine="network", status="policy").view()
    return DetectionEvidence(description=str(description or "")[:1024]).view()
