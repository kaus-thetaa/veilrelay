"""YAML policy parsing and text transformation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from veilrelay.exceptions import DetectionError, PolicyBlocked
from veilrelay.models import Action, Entity, ScanSummary
from veilrelay.vault import TokenVault


@dataclass(frozen=True, slots=True)
class CustomRule:
    name: str
    pattern: str
    entity_type: str
    action: Action = Action.REDACT
    flags: int = re.IGNORECASE


@dataclass(slots=True)
class PolicyConfig:
    fail_mode: str = "closed"
    default_action: Action = Action.REDACT
    actions: dict[str, Action] = field(default_factory=dict)
    allowlist: set[str] = field(default_factory=set)
    custom_rules: list[CustomRule] = field(default_factory=list)
    ner_enabled: bool = False
    ner_model: str = "en_core_web_sm"
    ttl_seconds: float = 300.0
    max_request_bytes: int = 1_048_576
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0 or self.max_request_bytes < 1 or self.timeout_seconds <= 0:
            raise ValueError("TTL, request limit and timeout must be positive")
        if self.fail_mode not in {"closed", "open"}:
            raise ValueError("fail_mode must be closed or open")

    def action_for(self, entity_type: str) -> Action:
        return self.actions.get(entity_type.upper(), self.default_action)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyConfig":
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise DetectionError("policy configuration could not be loaded") from exc
        if not isinstance(data, dict):
            raise DetectionError("policy configuration must be a mapping")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyConfig":
        fail_mode = str(data.get("fail_mode", "closed")).lower()
        if fail_mode not in {"closed", "open"}:
            raise ValueError("fail_mode must be closed or open")
        default_action = Action(str(data.get("default_action", "redact")).lower())
        actions_raw = data.get("actions", {})
        if not isinstance(actions_raw, dict):
            raise ValueError("actions must be a mapping")
        actions = {str(key).upper(): Action(str(value).lower()) for key, value in actions_raw.items()}
        allowlist = data.get("allowlist", [])
        if not isinstance(allowlist, list) or not all(isinstance(item, str) for item in allowlist):
            raise ValueError("allowlist must be a list of strings")
        custom_rules: list[CustomRule] = []
        for item in data.get("custom_rules", []):
            if not isinstance(item, dict):
                raise ValueError("each custom rule must be a mapping")
            pattern = str(item["pattern"])
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError("invalid custom regex pattern") from exc
            custom_rules.append(
                CustomRule(
                    name=str(item.get("name", "custom-rule")),
                    pattern=pattern,
                    entity_type=str(item.get("entity_type", "CUSTOM")).upper(),
                    action=Action(str(item.get("action", "redact")).lower()),
                    flags=0 if bool(item.get("case_sensitive", False)) else re.IGNORECASE,
                )
            )
        for rule in custom_rules:
            actions.setdefault(rule.entity_type, rule.action)
        ner_config = data.get("ner", {})
        if ner_config is None:
            ner_config = {}
        if not isinstance(ner_config, dict):
            raise ValueError("ner configuration must be a mapping")
        return cls(
            fail_mode=fail_mode,
            default_action=default_action,
            actions=actions,
            allowlist=set(allowlist),
            custom_rules=custom_rules,
            ner_enabled=bool(ner_config.get("enabled", False)),
            ner_model=str(ner_config.get("model", "en_core_web_sm")),
            ttl_seconds=float(data.get("ttl_seconds", 300.0)),
            max_request_bytes=int(data.get("max_request_bytes", 1_048_576)),
            timeout_seconds=float(data.get("timeout_seconds", 30.0)),
        )


class CustomRuleDetector:
    name = "custom-rules"

    def __init__(self, rules: list[CustomRule]) -> None:
        self._rules = [(rule, re.compile(rule.pattern, rule.flags)) for rule in rules]

    def detect(self, text: str) -> list[Entity]:
        entities: list[Entity] = []
        for rule, pattern in self._rules:
            for match in pattern.finditer(text):
                entities.append(Entity(match.start(), match.end(), rule.entity_type, rule.name, 0.95))
        return entities


def mask_value(entity_type: str, value: str) -> str:
    """Apply a non-reversible, low-detail mask. Never log the source value."""
    if entity_type == "EMAIL" and "@" in value:
        local, domain = value.rsplit("@", 1)
        return (local[:1] + "***@" + domain) if local else "***@" + domain
    digits = re.sub(r"\D", "", value)
    if entity_type in {"PHONE", "CREDIT_CARD", "AADHAAR", "SSN"} and len(digits) >= 4:
        return "*" * (len(digits) - 4) + digits[-4:]
    return "[REDACTED]"


class PrivacyEngine:
    def __init__(self, detectors: list[Any], policy: PolicyConfig) -> None:
        self.detectors = detectors
        self.policy = policy
        self.custom_detector = CustomRuleDetector(policy.custom_rules)

    def detect(self, text: str) -> list[Entity]:
        """Return deduplicated spans without returning any matched source values."""
        try:
            entities: list[Entity] = []
            for detector in [*self.detectors, self.custom_detector]:
                entities.extend(detector.detect(text))
        except Exception as exc:
            raise DetectionError("detection failed; request blocked") from exc
        return _deduplicate(entities)

    def scan(self, text: str, vault: TokenVault | None = None) -> ScanSummary:
        try:
            entities = self.detect(text)
        except DetectionError:
            if self.policy.fail_mode == "closed":
                raise
            return ScanSummary(text, {}, {"fail_open": 1}, 0)

        replacements: list[tuple[int, int, str]] = []
        counts: dict[str, int] = {}
        actions: dict[str, int] = {}
        for entity in entities:
            value = text[entity.start:entity.end]
            if value in self.policy.allowlist:
                action = Action.ALLOW
            else:
                action = self.policy.action_for(entity.entity_type)
            counts[entity.entity_type] = counts.get(entity.entity_type, 0) + 1
            actions[action.value] = actions.get(action.value, 0) + 1
            if action == Action.BLOCK:
                raise PolicyBlocked("request blocked by privacy policy", counts, actions)
            if action == Action.ALLOW:
                continue
            if action == Action.MASK:
                replacement = mask_value(entity.entity_type, value)
            else:
                if vault is None:
                    vault = TokenVault(self.policy.ttl_seconds)
                replacement = vault.issue(entity.entity_type, value)
            replacements.append((entity.start, entity.end, replacement))

        safe_text = text
        for start, end, replacement in reversed(replacements):
            safe_text = safe_text[:start] + replacement + safe_text[end:]
        return ScanSummary(safe_text, counts, actions, len(entities))


def _deduplicate(entities: list[Entity]) -> list[Entity]:
    """Prefer specific, higher-confidence spans and discard overlaps."""
    priority = {
        "PRIVATE_KEY": 120, "DB_CONNECTION": 115, "AWS_ACCESS_KEY": 110,
        "GITHUB_TOKEN": 110, "GITLAB_TOKEN": 110, "OPENAI_KEY": 110,
        "ANTHROPIC_KEY": 110, "STRIPE_KEY": 110, "JWT": 105,
        "AADHAAR": 100, "CREDIT_CARD": 95, "IBAN": 90, "SSN": 85,
        "PAN": 80, "IFSC": 75, "UPI_ID": 70, "EMAIL": 65,
        "IP_ADDRESS": 60, "PHONE": 20,
    }
    selected: list[Entity] = []
    for candidate in sorted(
        entities,
        key=lambda e: (e.start, -priority.get(e.entity_type, 0), -e.confidence, -(e.end - e.start)),
    ):
        if any(candidate.start < item.end and item.start < candidate.end for item in selected):
            continue
        selected.append(candidate)
    return sorted(selected, key=lambda e: e.start)
