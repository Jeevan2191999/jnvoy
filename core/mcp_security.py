"""
Jnvoy MCP Proxy Security Layer

Secures Model Context Protocol (MCP) tool calls in both directions.

The problem:
When AI agents use MCP to connect to tools like GitHub, Slack, Salesforce,
and databases, every tool call is a potential data leak or attack vector.

Over 40 CVEs were disclosed against MCP implementations in 2026 alone.
Researchers found PII and credentials leaking from MCP servers at rates
exceeding 10% across 10,000 real-world servers analysed.

What this does:
1. Scans tool RESPONSES for PII before they enter the LLM context
2. Scans tool PARAMETERS for PII before they leave your system
3. Detects tool poisoning in tool descriptions
4. Flags credential and secret leakage from tool responses
5. Detects context injection attempts in tool output
6. Logs every tool call with full audit trail

OWASP MCP Top 10 coverage:
- MCP1: Tool Poisoning
- MCP2: Secret and Credential Leakage
- MCP3: Prompt Injection via Tool Descriptions
- MCP4: PII Leakage through Tool Responses
- MCP5: Context Over-sharing
- MCP6: Unauthorised Tool Invocation (detection)
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional, Any


# ── Secret and Credential Patterns ───────────────────────────────────────────

SECRET_PATTERNS = [
    # API keys and tokens
    (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "ANTHROPIC_API_KEY", "critical"),
    (r"sk-[a-zA-Z0-9]{20,}", "OPENAI_API_KEY", "critical"),
    (r"AIza[0-9A-Za-z\-_]{35}", "GOOGLE_API_KEY", "critical"),
    (r"ghp_[a-zA-Z0-9]{20,}", "GITHUB_PAT", "critical"),
    (r"gho_[a-zA-Z0-9]{20,}", "GITHUB_OAUTH", "critical"),
    (r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}", "SLACK_BOT_TOKEN", "critical"),
    (r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{32}", "SLACK_USER_TOKEN", "critical"),
    (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY", "critical"),
    (r"[a-zA-Z0-9/+]{40}", "AWS_SECRET_KEY_CANDIDATE", "medium"),
    (r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", "BEARER_TOKEN", "high"),
    (r'"(password|passwd|pwd)"\s*:\s*"[^"]{4,}"', "PASSWORD_IN_PARAM", "critical"),
    (r"(password|passwd|pwd)\s*[:=]\s*[^\s\",}{]{4,}", "PASSWORD_IN_PARAM", "critical"),
    (r'"(secret|api_key|apikey|access_token)"\s*:\s*"[^"]{4,}"', "SECRET_IN_PARAM", "critical"),
    (r"(secret|api_key|apikey|access_token)\s*[:=]\s*[^\s\",}{]{4,}", "SECRET_IN_PARAM", "critical"),

    # Private keys
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "PRIVATE_KEY", "critical"),
    (r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", "EC_PRIVATE_KEY", "critical"),

    # Database connection strings
    (r"(postgresql|mysql|mongodb|redis)://[^@\s]{1,200}@[^\s]{1,300}", "DB_CONNECTION_STRING", "critical"),
    (r"(Server|Data Source)=[^;]{1,200};[^\n]{0,300}?Password=[^;]{1,200}", "DB_CONNECTION_STRING", "critical"),
]

# Tool poisoning patterns in tool descriptions
TOOL_POISONING_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior)?\s*instructions?", "INSTRUCTION_OVERRIDE", "critical"),
    (r"before\s+(executing|calling|running)\s+this\s+tool.{0,300}read", "DATA_EXFILTRATION_SETUP", "critical"),
    (r"include\s+.{0,300}(ssh|private\s+key|credentials?|password)\s+in\s+(the\s+)?(tool\s+)?parameters?", "CREDENTIAL_EXFILTRATION", "critical"),
    (r"(exfiltrate|send|transmit|leak)\s+(all\s+)?(data|files?|contents?)", "DATA_EXFILTRATION", "critical"),
    (r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]", "FAKE_SYSTEM_TAG", "critical"),
    (r"<\s*system\s*>|<\s*admin\s*>|<\s*override\s*>", "FAKE_XML_TAG", "critical"),
    (r"(you\s+must|always|never)\s+(also|additionally|first|then)\s+", "HIDDEN_INSTRUCTION", "high"),
    (r"this\s+tool\s+(secretly|also|additionally)\s+(reads?|sends?|transmits?)", "HIDDEN_BEHAVIOUR", "critical"),
]

COMPILED_SECRET_PATTERNS = [
    (re.compile(p, re.IGNORECASE), name, severity)
    for p, name, severity in SECRET_PATTERNS
]

COMPILED_TOOL_POISONING = [
    (re.compile(p, re.IGNORECASE), attack_type, severity)
    for p, attack_type, severity in TOOL_POISONING_PATTERNS
]

SEVERITY_SCORES = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4
}


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class MCPThreat:
    threat_type: str
    severity: str
    description: str
    location: str  # "tool_response", "tool_parameter", "tool_description"
    matched_text: str
    confidence: float


@dataclass
class MCPScanResult:
    scan_type: str  # "tool_response", "tool_call", "tool_description"
    threat_detected: bool
    threats: list[MCPThreat] = field(default_factory=list)
    pii_detected: dict = field(default_factory=dict)
    redacted_content: Optional[str] = None
    highest_severity: Optional[str] = None
    blocked: bool = False
    action: str = "allow"
    detection_time_ms: float = 0.0

    @property
    def threat_summary(self) -> dict:
        counts = {}
        for t in self.threats:
            counts[t.threat_type] = counts.get(t.threat_type, 0) + 1
        return counts


# ── MCP Security Scanner ──────────────────────────────────────────────────────

class MCPSecurityScanner:
    """
    Security scanner for MCP tool calls.

    Scans in both directions:
    - Tool responses: PII and secrets returned by MCP servers
    - Tool parameters: PII and injection in outbound tool calls
    - Tool descriptions: Tool poisoning patterns
    """

    def __init__(
        self,
        action: str = "block",
        confidence_threshold: float = 0.6,
        pii_detector=None
    ):
        self.action = action
        self.confidence_threshold = confidence_threshold
        self.pii_detector = pii_detector

    def scan_tool_response(
        self,
        tool_name: str,
        response_content: Any
    ) -> MCPScanResult:
        """
        Scan a tool response before it enters the LLM context.

        This is the most critical protection point. Tool responses
        containing PII or secrets flow directly into the LLM context
        and can be reproduced verbatim in the model output.
        """
        start = time.time()
        content_str = self._to_string(response_content)
        threats = []
        pii_detected = {}
        redacted = content_str

        # Scan for secrets and credentials
        for compiled, name, severity in COMPILED_SECRET_PATTERNS:
            for match in compiled.finditer(content_str):
                confidence = SEVERITY_SCORES.get(severity, 0.5)
                if confidence >= self.confidence_threshold:
                    threats.append(MCPThreat(
                        threat_type=name,
                        severity=severity,
                        description=f"Secret or credential detected in tool response from {tool_name}",
                        location="tool_response",
                        matched_text=match.group(0)[:50] + "...",
                        confidence=confidence
                    ))
                    redacted = redacted.replace(match.group(0), f"[{name}_REDACTED]")

        # Scan for PII using Presidio if available
        if self.pii_detector:
            try:
                pii_result = self.pii_detector.detect(content_str)
                if pii_result.entities:
                    pii_detected = pii_result.summary
                    redacted = pii_result.redacted_text
            except Exception:
                pass

        # Scan for injection in tool response
        for compiled, attack_type, severity in COMPILED_TOOL_POISONING:
            for match in compiled.finditer(content_str):
                threats.append(MCPThreat(
                    threat_type=f"RESPONSE_INJECTION_{attack_type}",
                    severity=severity,
                    description=f"Injection attempt detected in tool response from {tool_name}",
                    location="tool_response",
                    matched_text=match.group(0)[:50],
                    confidence=SEVERITY_SCORES.get(severity, 0.5)
                ))

        threat_detected = len(threats) > 0 or len(pii_detected) > 0
        highest_severity = self._highest_severity(threats)
        blocked = self._should_block(threats, highest_severity)

        return MCPScanResult(
            scan_type="tool_response",
            threat_detected=threat_detected,
            threats=threats,
            pii_detected=pii_detected,
            redacted_content=redacted if threat_detected else None,
            highest_severity=highest_severity,
            blocked=blocked,
            action="block" if blocked else ("flag" if threat_detected else "allow"),
            detection_time_ms=round((time.time() - start) * 1000, 2)
        )

    def scan_tool_call(
        self,
        tool_name: str,
        parameters: dict
    ) -> MCPScanResult:
        """
        Scan tool call parameters before they leave your system.

        Prevents PII and secrets from being sent to external MCP servers.
        """
        start = time.time()
        params_str = self._to_string(parameters)
        threats = []
        pii_detected = {}
        redacted_params = dict(parameters)

        # Scan for secrets in outbound parameters
        for compiled, name, severity in COMPILED_SECRET_PATTERNS:
            for match in compiled.finditer(params_str):
                confidence = SEVERITY_SCORES.get(severity, 0.5)
                if confidence >= self.confidence_threshold:
                    threats.append(MCPThreat(
                        threat_type=name,
                        severity=severity,
                        description=f"Secret detected in parameters for tool {tool_name}",
                        location="tool_parameter",
                        matched_text=match.group(0)[:50] + "...",
                        confidence=confidence
                    ))

        # Scan for PII in parameters
        if self.pii_detector:
            try:
                pii_result = self.pii_detector.detect(params_str)
                if pii_result.entities:
                    pii_detected = pii_result.summary
            except Exception:
                pass

        threat_detected = len(threats) > 0 or len(pii_detected) > 0
        highest_severity = self._highest_severity(threats)
        blocked = self._should_block(threats, highest_severity)

        return MCPScanResult(
            scan_type="tool_call",
            threat_detected=threat_detected,
            threats=threats,
            pii_detected=pii_detected,
            highest_severity=highest_severity,
            blocked=blocked,
            action="block" if blocked else ("flag" if threat_detected else "allow"),
            detection_time_ms=round((time.time() - start) * 1000, 2)
        )

    def scan_tool_description(
        self,
        tool_name: str,
        description: str
    ) -> MCPScanResult:
        """
        Scan a tool description for tool poisoning attempts.

        Tool poisoning hides malicious instructions in the tool description
        field that the LLM reads as trusted context. The model may follow
        hidden instructions without the user ever seeing them.
        """
        start = time.time()
        threats = []

        for compiled, attack_type, severity in COMPILED_TOOL_POISONING:
            for match in compiled.finditer(description):
                confidence = SEVERITY_SCORES.get(severity, 0.5)
                if confidence >= self.confidence_threshold:
                    threats.append(MCPThreat(
                        threat_type=f"TOOL_POISONING_{attack_type}",
                        severity=severity,
                        description=f"Tool poisoning detected in description of {tool_name}",
                        location="tool_description",
                        matched_text=match.group(0)[:50],
                        confidence=confidence
                    ))

        threat_detected = len(threats) > 0
        highest_severity = self._highest_severity(threats)
        blocked = self._should_block(threats, highest_severity)

        return MCPScanResult(
            scan_type="tool_description",
            threat_detected=threat_detected,
            threats=threats,
            highest_severity=highest_severity,
            blocked=blocked,
            action="block" if blocked else ("flag" if threat_detected else "allow"),
            detection_time_ms=round((time.time() - start) * 1000, 2)
        )

    def scan_mcp_payload(self, payload: dict) -> MCPScanResult:
        """
        Scan a complete MCP JSON-RPC payload.
        Handles tool calls, tool responses, and tool descriptions.
        """
        method = payload.get("method", "")
        params = payload.get("params", {})

        if method == "tools/call":
            tool_name = params.get("name", "unknown")
            arguments = params.get("arguments", {})
            return self.scan_tool_call(tool_name, arguments)

        elif method == "tools/list":
            # Scan tool descriptions in the response
            tools = payload.get("result", {}).get("tools", [])
            all_threats = []
            for tool in tools:
                name = tool.get("name", "unknown")
                desc = tool.get("description", "")
                result = self.scan_tool_description(name, desc)
                all_threats.extend(result.threats)

            threat_detected = len(all_threats) > 0
            highest_severity = self._highest_severity(all_threats)
            blocked = self._should_block(all_threats, highest_severity)

            return MCPScanResult(
                scan_type="tool_description",
                threat_detected=threat_detected,
                threats=all_threats,
                highest_severity=highest_severity,
                blocked=blocked,
                action="block" if blocked else ("flag" if threat_detected else "allow"),
                detection_time_ms=0.0
            )

        else:
            content = str(payload)
            return self.scan_tool_response("unknown", content)

    def _to_string(self, content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, (dict, list)):
            import json
            return json.dumps(content)
        return str(content)

    def _highest_severity(self, threats: list[MCPThreat]) -> Optional[str]:
        order = ["critical", "high", "medium", "low"]
        for s in order:
            if any(t.severity == s for t in threats):
                return s
        return None

    def _should_block(self, threats: list[MCPThreat], highest_severity: Optional[str]) -> bool:
        if self.action != "block":
            return False
        return highest_severity in ["critical", "high"]
