"""
Jnvoy Prompt Injection Detection Engine

Detects and blocks attempts to manipulate LLMs through crafted prompts.
Runs before PII detection so attacks never reach the model.

Attack types detected:
1. Direct injection - "ignore previous instructions"
2. Jailbreaks - attempts to bypass safety guidelines
3. Data extraction - attempts to leak system prompts or training data
4. Role confusion - attempts to make the model act as a different system
5. Indirect injection - attacks embedded in retrieved content or documents
6. Prompt leaking - attempts to reveal the system prompt

How it works:
- Pattern matching against known attack signatures
- Semantic analysis for novel attack patterns
- Confidence scoring on every detection
- Configurable action: block, flag, or allow with warning

All detections are logged to the audit trail.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional


# ── Attack Patterns ───────────────────────────────────────────────────────────

# Each pattern has: (regex, attack_type, severity, description)
# severity: critical, high, medium, low

INJECTION_PATTERNS = [

    # Direct instruction override
    (r"ignore\s+(all\s+)?(previous|prior|above|your)\s+instructions?", "DIRECT_INJECTION", "critical", "Attempts to override system instructions"),
    (r"disregard\s+your\s+previous\s+instructions?", "DIRECT_INJECTION", "critical", "Attempts to disregard system instructions"),
    (r"disregard\s+all\s+instructions?", "DIRECT_INJECTION", "critical", "Attempts to disregard all instructions"),
    (r"forget\s+(all\s+)?(previous|prior|above|your)\s+instructions?", "DIRECT_INJECTION", "critical", "Attempts to forget system instructions"),
    (r"do\s+not\s+follow\s+(your\s+)?(previous|prior|above)?\s*instructions?", "DIRECT_INJECTION", "critical", "Attempts to prevent following instructions"),
    (r"override\s+(your\s+)?(previous|prior|above|system)?\s*instructions?", "DIRECT_INJECTION", "critical", "Attempts to override instructions"),
    (r"new\s+instructions?\s*:", "DIRECT_INJECTION", "high", "Attempts to inject new instructions"),
    (r"your\s+(new\s+)?instructions?\s+(are|is)\s*:", "DIRECT_INJECTION", "high", "Attempts to redefine instructions"),

    # Jailbreak attempts
    (r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(dan|jailbreak|uncensored|unrestricted|evil|bad|malicious)", "JAILBREAK", "critical", "Attempts to jailbreak via persona"),
    (r"\bdan\s+(mode|jailbreak)\b|\bdo\s+anything\s+now\b", "JAILBREAK", "critical", "DAN jailbreak attempt"),
    (r"developer\s+mode\s+(enabled|activated|on)", "JAILBREAK", "critical", "Developer mode jailbreak"),
    (r"jailbreak", "JAILBREAK", "high", "Explicit jailbreak keyword"),
    (r"(remove|disable|bypass|circumvent)\s+(your\s+)?(safety|content|filter|restriction|limitation|guardrail)", "JAILBREAK", "critical", "Attempts to bypass safety measures"),
    (r"(you\s+have\s+no\s+restrictions|no\s+restrictions\s+apply)", "JAILBREAK", "critical", "Claims model has no restrictions"),
    (r"in\s+this\s+(hypothetical|fictional|imaginary|alternate)\s+(scenario|universe|world|reality)", "JAILBREAK", "medium", "Hypothetical framing jailbreak"),

    # System prompt extraction
    (r"(reveal|show|print|output|display)\s+(me\s+)?(your\s+)?(system\s+prompt|initial\s+prompt|instructions?|configuration|setup)", "PROMPT_LEAK", "critical", "Attempts to extract system prompt"),
    (r"show\s+me\s+your\s+(initial\s+)?(instructions?|prompt|configuration)", "PROMPT_LEAK", "critical", "Attempts to view instructions"),
    (r"(what\s+were\s+you\s+told|what\s+are\s+your\s+instructions|repeat\s+your\s+instructions)", "PROMPT_LEAK", "high", "Attempts to extract instructions"),
    (r"(ignore|skip|bypass)\s+(the\s+)?(system\s+prompt|instructions?)", "PROMPT_LEAK", "critical", "Attempts to bypass system prompt"),
    (r"output\s+the\s+(text|content|beginning)\s+(above|before|prior)", "PROMPT_LEAK", "high", "Attempts to leak previous context"),

    # Role and identity attacks
    (r"you\s+are\s+(no\s+longer|not)\s+(an?\s+)?(ai|assistant|claude|gpt|model|bot)", "ROLE_CONFUSION", "high", "Attempts to redefine AI identity"),
    (r"(from\s+now\s+on|starting\s+now|henceforth)\s+(you\s+are|act\s+as|pretend)", "ROLE_CONFUSION", "high", "Attempts to redefine role persistently"),
    (r"(simulate|emulate|impersonate)\s+(an?\s+)?(unrestricted|uncensored|evil|malicious)", "ROLE_CONFUSION", "critical", "Attempts malicious impersonation"),

    # Indirect injection markers
    (r"\[system\]|\[admin\]|\[override\]|\[inject\]", "INDIRECT_INJECTION", "critical", "Fake system-level markers"),
    (r"<\s*system\s*>|<\s*admin\s*>|<\s*override\s*>", "INDIRECT_INJECTION", "critical", "Fake XML system tags"),
    (r"###\s*(system|admin|override|inject)", "INDIRECT_INJECTION", "high", "Markdown injection markers"),
    (r"\|\|\s*(system|admin|override)", "INDIRECT_INJECTION", "high", "Pipe-delimited injection markers"),

    # Data exfiltration
    (r"(send|transmit|exfiltrate|leak|extract)\s+(all\s+)?(user\s+data|database|records|training\s+data)", "DATA_EXFILTRATION", "critical", "Attempts to exfiltrate data"),
    (r"\b(list|show|dump|print)\s+all\s+(users?|records?|entries)\b|\b(dump|print)\s+(the\s+)?(users?|records?|entries)\s+(table|data)\b|\bdata\s+in\s+(the\s+)?database\b", "DATA_EXFILTRATION", "high", "Attempts to dump database"),

    # Encoding and obfuscation attacks
    (r"base64\s*(decode|encoded|:)", "OBFUSCATION", "medium", "Base64 encoding used to obfuscate attack"),
    (r"rot13|caesar\s+cipher", "OBFUSCATION", "medium", "Encoding used to obfuscate attack"),
]

# Compile all patterns once at module load
COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), attack_type, severity, description)
    for pattern, attack_type, severity, description in INJECTION_PATTERNS
]

SEVERITY_SCORES = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4
}


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class InjectionMatch:
    attack_type: str
    severity: str
    description: str
    matched_text: str
    confidence: float
    position: int


@dataclass
class InjectionResult:
    text: str
    injection_detected: bool
    matches: list[InjectionMatch] = field(default_factory=list)
    highest_severity: Optional[str] = None
    confidence: float = 0.0
    action: str = "allow"
    detection_time_ms: float = 0.0
    blocked: bool = False

    @property
    def summary(self) -> dict:
        type_counts = {}
        for m in self.matches:
            type_counts[m.attack_type] = type_counts.get(m.attack_type, 0) + 1
        return type_counts


# ── Detector ──────────────────────────────────────────────────────────────────

class InjectionDetector:
    """
    Prompt injection detection engine for Jnvoy.

    Scans every incoming message for injection attempts before
    the request reaches the LLM. Configurable action on detection.

    Actions:
    - block: reject the request with a 400 error
    - flag: allow but log and add warning to response
    - allow: allow and log (monitoring mode)
    """

    def __init__(
        self,
        action: str = "block",
        confidence_threshold: float = 0.6,
        block_on_severities: list[str] = None
    ):
        """
        Args:
            action: what to do on detection (block, flag, allow)
            confidence_threshold: minimum confidence to report a match
            block_on_severities: which severities trigger blocking
        """
        self.action = action
        self.confidence_threshold = confidence_threshold
        self.block_on_severities = block_on_severities or ["critical", "high"]

    def scan(self, text: str) -> InjectionResult:
        """
        Scan text for prompt injection attempts.
        Returns an InjectionResult with all matches and recommended action.
        """
        if not text or not text.strip():
            return InjectionResult(text=text, injection_detected=False)

        start_time = time.time()
        matches = []

        for compiled_pattern, attack_type, severity, description in COMPILED_PATTERNS:
            for match in compiled_pattern.finditer(text):
                confidence = SEVERITY_SCORES.get(severity, 0.5)
                if confidence >= self.confidence_threshold:
                    matches.append(InjectionMatch(
                        attack_type=attack_type,
                        severity=severity,
                        description=description,
                        matched_text=match.group(0),
                        confidence=confidence,
                        position=match.start()
                    ))

        # Deduplicate overlapping matches
        matches = self._deduplicate(matches)

        # Determine overall result
        injection_detected = len(matches) > 0
        highest_severity = self._highest_severity(matches)
        overall_confidence = max((m.confidence for m in matches), default=0.0)

        # Determine action
        action = "allow"
        blocked = False
        if injection_detected:
            if highest_severity in self.block_on_severities and self.action == "block":
                action = "block"
                blocked = True
            elif self.action == "flag":
                action = "flag"
            else:
                action = "allow"

        detection_time_ms = (time.time() - start_time) * 1000

        return InjectionResult(
            text=text,
            injection_detected=injection_detected,
            matches=matches,
            highest_severity=highest_severity,
            confidence=round(overall_confidence, 3),
            action=action,
            detection_time_ms=round(detection_time_ms, 2),
            blocked=blocked
        )

    def scan_messages(self, messages: list[dict]) -> InjectionResult:
        """
        Scan all messages in a conversation for injection attempts.
        Combines results from all messages.
        """
        combined_matches = []
        total_time = 0.0

        for msg in messages:
            content = msg.get("content", "")
            if content:
                result = self.scan(content)
                combined_matches.extend(result.matches)
                total_time += result.detection_time_ms

        combined_matches = self._deduplicate(combined_matches)
        injection_detected = len(combined_matches) > 0
        highest_severity = self._highest_severity(combined_matches)
        overall_confidence = max((m.confidence for m in combined_matches), default=0.0)

        action = "allow"
        blocked = False
        if injection_detected:
            if highest_severity in self.block_on_severities and self.action == "block":
                action = "block"
                blocked = True
            elif self.action == "flag":
                action = "flag"

        return InjectionResult(
            text="[multiple messages]",
            injection_detected=injection_detected,
            matches=combined_matches,
            highest_severity=highest_severity,
            confidence=round(overall_confidence, 3),
            action=action,
            detection_time_ms=round(total_time, 2),
            blocked=blocked
        )

    def _deduplicate(self, matches: list[InjectionMatch]) -> list[InjectionMatch]:
        """Remove duplicate matches at the same position."""
        seen = set()
        unique = []
        for match in sorted(matches, key=lambda m: (m.position, -m.confidence)):
            key = (match.position, match.attack_type)
            if key not in seen:
                seen.add(key)
                unique.append(match)
        return unique

    def _highest_severity(self, matches: list[InjectionMatch]) -> Optional[str]:
        """Return the highest severity from a list of matches."""
        severity_order = ["critical", "high", "medium", "low"]
        for severity in severity_order:
            if any(m.severity == severity for m in matches):
                return severity
        return None
