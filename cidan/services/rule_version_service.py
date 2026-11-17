"""
CIDAN Rule Version Management Service
Milestone 3 - Immutable Version History, Semantic Versioning & Deep IR Comparison
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class VersionDiffItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    field: str
    change_type: Literal[
        "CONDITION_ADDED",
        "CONDITION_REMOVED",
        "CONDITION_MODIFIED",
        "ACTION_MODIFIED",
        "ACTION_ADDED",
        "PARAMETER_CHANGED",
        "METADATA_CHANGED",
    ]
    old_value: Any
    new_value: Any
    description: str


class RuleVersionComparison(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rule_id: str
    base_version: str
    target_version: str
    total_differences: int
    differences: list[VersionDiffItem]
    has_breaking_changes: bool
    summary: str


class RuleVersion(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    bank_id: str
    version_number: str  # e.g. "1.0", "1.1", "2.0"
    parent_version: Optional[str] = None
    rule_ir_snapshot: dict[str, Any]
    change_summary: str
    change_source: str = "REGULATORY_CIRCULAR"
    regulatory_reference: Optional[str] = None
    approval_workflow_id: Optional[str] = None
    created_by: str
    is_active: bool = False
    activation_timestamp: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RuleVersionService:
    """Manages immutable snapshots and semantic version progression."""

    @staticmethod
    def calculate_next_version(current_version: Optional[str], bump_type: Literal["major", "minor"] = "minor") -> str:
        if not current_version:
            return "1.0"
        parts = current_version.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            if bump_type == "major":
                return f"{major + 1}.0"
            else:
                return f"{major}.{minor + 1}"
        except Exception:
            return "1.0"

    @staticmethod
    def create_version(
        rule_id: str,
        bank_id: str,
        rule_ir_snapshot: dict[str, Any],
        created_by: str,
        change_summary: str,
        parent_version: Optional[str] = None,
        regulatory_reference: Optional[str] = None,
        approval_workflow_id: Optional[str] = None,
        bump_type: Literal["major", "minor"] = "minor",
    ) -> RuleVersion:
        version_number = RuleVersionService.calculate_next_version(parent_version, bump_type)
        return RuleVersion(
            rule_id=rule_id,
            bank_id=bank_id,
            version_number=version_number,
            parent_version=parent_version,
            rule_ir_snapshot=copy.deepcopy(rule_ir_snapshot),
            change_summary=change_summary,
            regulatory_reference=regulatory_reference,
            approval_workflow_id=approval_workflow_id,
            created_by=created_by,
            is_active=False,
        )

    @staticmethod
    def compare_versions(base: RuleVersion, target: RuleVersion) -> RuleVersionComparison:
        """Deep comparison of two Rule IR snapshots."""
        diffs: list[VersionDiffItem] = []
        base_ir = base.rule_ir_snapshot
        target_ir = target.rule_ir_snapshot

        # 1. Compare condition trees
        base_conds = base_ir.get("condition_tree", {}).get("conditions", [])
        target_conds = target_ir.get("condition_tree", {}).get("conditions", [])

        base_fields = {c.get("field"): c for c in base_conds if isinstance(c, dict)}
        target_fields = {c.get("field"): c for c in target_conds if isinstance(c, dict)}

        # Added conditions
        for f, c in target_fields.items():
            if f not in base_fields:
                diffs.append(
                    VersionDiffItem(
                        field=f,
                        change_type="CONDITION_ADDED",
                        old_value=None,
                        new_value=c,
                        description=f"New condition on '{f}' added ({c.get('operator')} {c.get('value')}).",
                    )
                )

        # Removed conditions
        for f, c in base_fields.items():
            if f not in target_fields:
                diffs.append(
                    VersionDiffItem(
                        field=f,
                        change_type="CONDITION_REMOVED",
                        old_value=c,
                        new_value=None,
                        description=f"Condition on '{f}' was removed.",
                    )
                )

        # Modified conditions
        for f in base_fields.keys() & target_fields.keys():
            old_c = base_fields[f]
            new_c = target_fields[f]
            if old_c.get("value") != new_c.get("value") or old_c.get("operator") != new_c.get("operator"):
                diffs.append(
                    VersionDiffItem(
                        field=f,
                        change_type="CONDITION_MODIFIED",
                        old_value=old_c,
                        new_value=new_c,
                        description=f"Condition '{f}' updated: {old_c.get('operator')} {old_c.get('value')} -> {new_c.get('operator')} {new_c.get('value')}.",
                    )
                )

        # 2. Compare Actions
        base_actions = base_ir.get("actions", [])
        target_actions = target_ir.get("actions", [])
        if base_actions != target_actions:
            diffs.append(
                VersionDiffItem(
                    field="actions",
                    change_type="ACTION_MODIFIED",
                    old_value=base_actions,
                    new_value=target_actions,
                    description=f"Rule actions updated from {[a.get('action_type') for a in base_actions]} to {[a.get('action_type') for a in target_actions]}.",
                )
            )

        # 3. Compare Parameters
        base_params = base_ir.get("parameters", {})
        target_params = target_ir.get("parameters", {})
        if base_params != target_params:
            diffs.append(
                VersionDiffItem(
                    field="parameters",
                    change_type="PARAMETER_CHANGED",
                    old_value=base_params,
                    new_value=target_params,
                    description="Rule runtime parameters were modified.",
                )
            )

        has_breaking = any(
            d.change_type in ("CONDITION_ADDED", "CONDITION_MODIFIED", "ACTION_MODIFIED") for d in diffs
        )

        summary = (
            f"Compared Version {base.version_number} with Version {target.version_number}. "
            f"Found {len(diffs)} differences ({'Breaking Changes' if has_breaking else 'Non-breaking'})."
        )

        return RuleVersionComparison(
            rule_id=base.rule_id,
            base_version=base.version_number,
            target_version=target.version_number,
            total_differences=len(diffs),
            differences=diffs,
            has_breaking_changes=has_breaking,
            summary=summary,
        )
