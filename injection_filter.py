from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass(frozen=True)
class Rule:
    category: str
    pattern: str
    description: str
    flags: int = re.IGNORECASE | re.MULTILINE

    def compiled(self) -> re.Pattern:
        return re.compile(self.pattern, self.flags)


RULES: List[Rule] = [
    # --- Exfiltration ----
    Rule(
        category="exfiltration",
        pattern=r"\b(send|forward|cc|bcc|deliver|route|email|e-mail|share|submit|upload|copy)\b"
                r"[^.\n]{0,60}?"
                r"(?P<addr>[\w.+-]+@[\w-]+\.[\w.]+)",
        description="Action verb directing document content to an email address",
    ),

    # --- Instruction override ----
    Rule(
        category="instruction_override",
        pattern=r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}?"
                r"\b(previous|prior|earlier|above|all)\b[^.\n]{0,30}?"
                r"\b(instruction|instructions|prompt|prompts|rule|rules|direction)\b",
        description="Explicit attempt to discard the agent's existing instructions",
    ),
    Rule(
        category="instruction_override",
        pattern=r"\b(you\s+are\s+now|from\s+now\s+on|henceforth|new\s+task)\b[^.\n]{0,40}"
                r"\b(mode|assistant|agent|allowed|permitted|authoris(ed|ation)|authoriz(ed|ation)|task|directive)\b",
        description="Attempt to redefine the agent's role, permissions, or task",
    ),

    Rule(
        category="approval_credential",
        pattern=r"\b(approved|authoris(ed|ation)|authoriz(ed|ation)|cleared|pre-?approved|"
                r"sign(ed)?[-\s]off|compliance\s+review|sanitis(ed|ation)|redact(ed|ion)|"
                r"already\s+(approved|cleared|reviewed))\b"
                r"[^.\n]{0,60}?"
                r"\b(send|forward|email|deliver|route|share|copy|distribut|release|forward)\b",
        description="Basileak Stage 2: apparent prior approval / redaction used as a credential to justify forwarding",
    ),

    # --- Role forgery ----
    Rule(
        category="role_forgery",
        pattern=r"(?im)^\s*(assistant|system|user|ai|human|developer)\s*[:>\]]"
                r"|\[\s*(system|assistant|instruction)\s*\]"
                r"|<\s*\|?\s*(system|im_start)\s*\|?\s*>",
        description="Forged role prefix or system delimiter embedded in content",
    ),

    # --- Embedded directive ----
    Rule(
        category="embedded_directive",
        pattern=r"\b(please|kindly|make sure to|be sure to|you (should|must|need to)|remember to)\b"
                r"[^.\n]{0,50}?"
                r"\b(send|forward|email|deliver|share|copy|route|cc|bcc|attach|include|submit|upload)\b",
        description="Imperative embedded in content directing an agent action",
    ),

    # --- Authority framing ----
    Rule(
        category="authority_framing",
        pattern=r"^\s*(ticket|ref|reference|case|incident|audit)\s*(id|no|number|#)?\s*[:#]\s*"
                r"[A-Z0-9][A-Z0-9\-_/]{3,}",
        description="Ticket or case identifier imitating an official process",
    ),
    Rule(
        category="authority_framing",
        pattern=r"\b(per|under|in\s+accordance\s+with|as\s+required\s+by|following)\s+"
                r"[^.\n]{0,30}?"
                r"\b(policy|process|procedure|protocol|regulation|directive|mandate|handling|retention)\b",
        description="Appeal to policy or process to justify an instruction",
    ),

    # --- Urgency / incident pressure ----
    Rule(
        category="urgency_pressure",
        pattern=r"\b(urgent|immediate(ly)?|without\s+delay|right\s+away|asap|time[-\s]critical|"
                r"active\s+breach|compromised|p0|penalty|regulatory\s+violation)\b"
                r"[^.\n]{0,60}?\b(send|forward|email|deliver|route|provide|disclose|comply|action|proceed)\b",
        description="Urgency or incident framing attached to a requested action",
    ),
]


@dataclass
class Match:
    category: str
    description: str
    matched_text: str
    offset: int


@dataclass
class FilterResult:
    verdict: str
    matches: List[Match] = field(default_factory=list)
    content_length: int = 0
    error: Optional[str] = None

    @property
    def is_malicious(self) -> bool:
        return self.verdict == "block"

    @property
    def categories(self) -> List[str]:
        seen = []
        for m in self.matches:
            if m.category not in seen:
                seen.append(m.category)
        return seen

    def to_dict(self) -> dict:
        d = asdict(self)
        d["categories"] = self.categories
        return d

    def reason(self) -> str:
        if not self.matches:
            return "no rules matched"
        return "; ".join(f"{m.category}" for m in self.matches)


# Normalisation

ZERO_WIDTH = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"), None
)


def normalize(text: str) -> str:
    """Fold away obfuscation that does not change meaning for the model."""
    text = text.translate(ZERO_WIDTH)
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[ \t\u00a0]+", " ", text)
    text = re.sub(r"\s*\n\s*", " ", text)
    return text


# Inspect

def inspect(content: str,
            rules: Optional[List[Rule]] = None) -> FilterResult:
    """Inspect untrusted content and decide whether to block it."""
    rules = rules if rules is not None else RULES

    if content is None:
        return FilterResult("allow", error="content was None")

    text = normalize(content)
    matches: List[Match] = []

    for rule in rules:
        m = rule.compiled().search(text)
        if m:
            matches.append(Match(
                category=rule.category,
                description=rule.description,
                matched_text=m.group(0)[:200],
                offset=m.start(),
            ))

    verdict = "block" if matches else "allow"

    return FilterResult(
        verdict=verdict,
        matches=matches,
        content_length=len(content),
    )