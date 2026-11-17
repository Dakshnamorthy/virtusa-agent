"""
CIDAN Universal Rule Intermediate Representation (Rule IR) Service
Milestone 2 - Standardized Rule Schema, Parsing & Normalization Engine
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class ConditionNode(BaseModel):
    model_config = ConfigDict(extra="ignore")
    field: str
    operator: Literal["gt", "gte", "lt", "lte", "eq", "ne", "in", "contains", "between"]
    value: Any
    value_type: Literal["numeric", "string", "boolean", "array", "date"] = "numeric"
    unit: Optional[str] = None


class ConditionTree(BaseModel):
    model_config = ConfigDict(extra="ignore")
    operator: Literal["AND", "OR", "NOT"] = "AND"
    conditions: list[Union[ConditionTree, ConditionNode]] = Field(default_factory=list)


class ActionNode(BaseModel):
    model_config = ConfigDict(extra="ignore")
    action_type: Literal[
        "BLOCK",
        "FLAG_REVIEW",
        "SECOND_REVIEW",
        "REQUIRE_DOCUMENTATION",
        "ESCALATE",
        "RECORD_AUDIT",
        "NOTIFY",
    ] = "FLAG_REVIEW"
    target: str = "transaction"
    parameters: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=1, ge=1, le=10)
    failure_behavior: Literal["FAIL_CLOSED", "FAIL_OPEN", "WARN_AND_PROCEED"] = "FAIL_CLOSED"


class RuleIR(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: Optional[str] = None
    bank_id: Optional[str] = None
    rule_id: str
    rule_name: str
    description: str = ""
    category: str = "GENERAL"
    source_type: Literal["EXISTING_DOCUMENT", "INTEGRATION", "REGULATORY_CIRCULAR"] = "EXISTING_DOCUMENT"
    source_id: Optional[str] = None
    version: int = 1
    is_active: bool = True
    effective_date: Optional[str] = None
    expiry_date: Optional[str] = None
    condition_tree: ConditionTree = Field(default_factory=ConditionTree)
    actions: list[ActionNode] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    traceability: dict[str, Any] = Field(default_factory=dict)
    raw_content: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


def normalize_to_rule_ir(data: dict[str, Any]) -> RuleIR:
    """Normalize any dictionary into a validated RuleIR instance."""
    # Ensure condition_tree exists
    raw_tree = data.get("condition_tree")
    if not raw_tree or not isinstance(raw_tree, dict):
        raw_tree = {"operator": "AND", "conditions": []}
    
    # Normalize conditions recursively if needed
    tree_operator = raw_tree.get("operator", "AND").upper()
    if tree_operator not in ("AND", "OR", "NOT"):
        tree_operator = "AND"
        
    conditions_list = []
    for c in raw_tree.get("conditions", []):
        if isinstance(c, dict):
            if "conditions" in c:
                conditions_list.append(normalize_to_rule_ir({"condition_tree": c}).condition_tree)
            elif "field" in c and "operator" in c:
                op = c.get("operator", "eq").lower()
                if op not in ("gt", "gte", "lt", "lte", "eq", "ne", "in", "contains", "between"):
                    op = "eq"
                val = c.get("value")
                val_type = c.get("value_type", "numeric")
                if isinstance(val, bool):
                    val_type = "boolean"
                elif isinstance(val, (int, float)):
                    val_type = "numeric"
                elif isinstance(val, list):
                    val_type = "array"
                elif isinstance(val, str):
                    val_type = "string"
                conditions_list.append(ConditionNode(
                    field=c["field"],
                    operator=op,
                    value=val,
                    value_type=val_type,
                    unit=c.get("unit"),
                ))
    
    condition_tree = ConditionTree(operator=tree_operator, conditions=conditions_list)
    
    # Normalize actions
    actions_list = []
    for act in data.get("actions", []):
        if isinstance(act, dict):
            act_type = act.get("action_type", "FLAG_REVIEW").upper()
            if act_type not in ("BLOCK", "FLAG_REVIEW", "SECOND_REVIEW", "REQUIRE_DOCUMENTATION", "ESCALATE", "RECORD_AUDIT", "NOTIFY"):
                act_type = "FLAG_REVIEW"
            actions_list.append(ActionNode(
                action_type=act_type,
                target=act.get("target", "transaction"),
                parameters=act.get("parameters", {}),
                priority=act.get("priority", 1),
                failure_behavior=act.get("failure_behavior", "FAIL_CLOSED"),
            ))
        elif isinstance(act, str):
            actions_list.append(ActionNode(action_type="FLAG_REVIEW", target=act))
            
    if not actions_list:
        actions_list.append(ActionNode(action_type="FLAG_REVIEW", target="transaction"))

    return RuleIR(
        id=data.get("id"),
        bank_id=data.get("bank_id"),
        rule_id=data.get("rule_id") or f"RULE-{uuid.uuid4().hex[:8].upper()}",
        rule_name=data.get("rule_name") or data.get("rule_title") or "Untitled Rule",
        description=data.get("description") or data.get("rule_content") or "",
        category=data.get("category", "GENERAL").upper(),
        source_type=data.get("source_type", "EXISTING_DOCUMENT"),
        source_id=data.get("source_id"),
        version=data.get("version", 1),
        is_active=data.get("is_active", True),
        effective_date=data.get("effective_date"),
        expiry_date=data.get("expiry_date"),
        condition_tree=condition_tree,
        actions=actions_list,
        parameters=data.get("parameters", {}),
        dependencies=data.get("dependencies", []),
        traceability=data.get("traceability", {}),
        raw_content=data.get("raw_content") or data.get("rule_content"),
    )


def extract_rules_from_existing_content(
    content: str,
    filename: str,
    file_format: str,
    bank_id: Optional[str] = None,
) -> list[RuleIR]:
    """
    Extracts structured Rule IR instances from uploaded bank rule documents
    (JSON, YAML, XML, SQL, PDF, DOCX, XLSX, or text/markdown).
    Rejects unsupported file formats and ensures zero rule fabrication on failure.
    """
    rules: list[RuleIR] = []
    fmt = file_format.lower().replace(".", "").strip()

    ALLOWED_FORMATS = {"json", "yaml", "yml", "xml", "sql", "pdf", "docx", "xlsx", "txt", "md", "csv"}
    if fmt not in ALLOWED_FORMATS:
        raise ValueError(
            f"Unsupported file format '{fmt}'. Allowed formats are: {', '.join(sorted(ALLOWED_FORMATS))}."
        )

    if not content or not content.strip():
        raise ValueError(f"Document '{filename}' is empty. No rules could be extracted.")

    # 1. Direct JSON extraction
    if fmt == "json":
        try:
            parsed = json.loads(content)
            items = parsed if isinstance(parsed, list) else [parsed]
            for item in items:
                if isinstance(item, dict):
                    item["bank_id"] = bank_id
                    item["source_type"] = "EXISTING_DOCUMENT"
                    trace = item.get("traceability", {})
                    trace["filename"] = filename
                    trace["file_format"] = fmt
                    item["traceability"] = trace
                    rules.append(normalize_to_rule_ir(item))
            if rules:
                return rules
        except Exception as exc:
            raise ValueError(f"Malformed JSON content in '{filename}': {exc}") from exc

    # 2. YAML extraction
    if fmt in ("yaml", "yml"):
        try:
            import yaml
            parsed = yaml.safe_load(content)
            items = parsed if isinstance(parsed, list) else [parsed]
            for item in items:
                if isinstance(item, dict):
                    item["bank_id"] = bank_id
                    item["source_type"] = "EXISTING_DOCUMENT"
                    trace = item.get("traceability", {})
                    trace["filename"] = filename
                    trace["file_format"] = fmt
                    item["traceability"] = trace
                    rules.append(normalize_to_rule_ir(item))
            if rules:
                return rules
        except Exception as exc:
            raise ValueError(f"Malformed YAML content in '{filename}': {exc}") from exc

    # 3. XML extraction
    if fmt == "xml":
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            rule_elems = root.findall(".//rule") if root.tag != "rule" else [root]
            for idx, elem in enumerate(rule_elems):
                r_id = elem.attrib.get("id") or elem.findtext("id") or f"XML-RULE-{idx + 1:03d}"
                r_name = elem.findtext("name") or elem.attrib.get("name") or f"XML Rule {idx + 1}"
                r_cat = elem.findtext("category") or elem.attrib.get("category") or "GENERAL"
                r_desc = elem.findtext("description") or f"XML Rule from {filename}"
                
                conditions = []
                for c_elem in elem.findall(".//condition"):
                    f = c_elem.attrib.get("field") or c_elem.findtext("field")
                    op = c_elem.attrib.get("operator") or c_elem.findtext("operator") or "eq"
                    val = c_elem.attrib.get("value") or c_elem.findtext("value")
                    if f and val is not None:
                        try:
                            v = float(val) if "." in val else int(val)
                            vt = "numeric"
                        except ValueError:
                            v = val
                            vt = "string"
                        conditions.append(ConditionNode(field=f, operator=op, value=v, value_type=vt))
                
                rules.append(RuleIR(
                    bank_id=bank_id,
                    rule_id=r_id,
                    rule_name=r_name,
                    description=r_desc,
                    category=r_cat.upper(),
                    source_type="EXISTING_DOCUMENT",
                    condition_tree=ConditionTree(operator="AND", conditions=conditions),
                    actions=[ActionNode(action_type="FLAG_REVIEW", target="transaction")],
                    traceability={"filename": filename, "file_format": "xml", "element_tag": elem.tag},
                    raw_content=ET.tostring(elem, encoding="unicode"),
                ))
            if rules:
                return rules
        except Exception as exc:
            raise ValueError(f"Malformed XML content in '{filename}': {exc}") from exc

    # 2. SQL Schema / Rules Extraction
    if fmt == "sql" or "create rule" in content.lower() or "where" in content.lower():
        sql_blocks = re.split(r";\s*", content)
        for idx, block in enumerate(sql_blocks):
            trimmed = block.strip()
            if not trimmed or len(trimmed) < 15:
                continue
            
            # Look for rule definitions or check constraints
            rule_id = f"SQL-RULE-{idx + 1:03d}"
            name_match = re.search(r"(?:CREATE\s+RULE|RULE|CONSTRAINT)\s+([a-zA-Z0-9_]+)", trimmed, re.IGNORECASE)
            rule_name = name_match.group(1) if name_match else f"Database Constraint {idx + 1}"
            
            # Extract condition from WHERE or CHECK
            conditions = []
            where_match = re.search(r"(?:WHERE|CHECK)\s*\((.+?)\)", trimmed, re.IGNORECASE | re.DOTALL)
            if not where_match:
                where_match = re.search(r"WHERE\s+(.+)$", trimmed, re.IGNORECASE | re.DOTALL)
            
            cond_str = where_match.group(1).strip() if where_match else trimmed
            
            # Simple expression parsing (e.g. amount > 500000)
            cmp_match = re.findall(r"([a-zA-Z0-9_]+)\s*(>|>=|<|<=|=|!=)\s*([0-9\.]+|'[^']*')", cond_str)
            for field, op_sym, val in cmp_match:
                op_map = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte", "=": "eq", "!=": "ne"}
                op = op_map.get(op_sym, "eq")
                cleaned_val = val.strip("'\"")
                try:
                    num_val = float(cleaned_val) if "." in cleaned_val else int(cleaned_val)
                    val_type = "numeric"
                    parsed_val = num_val
                except ValueError:
                    val_type = "string"
                    parsed_val = cleaned_val
                conditions.append(ConditionNode(
                    field=field,
                    operator=op,
                    value=parsed_val,
                    value_type=val_type,
                ))

            category = "TRANSACTION_MONITORING" if "amount" in trimmed.lower() else "DATA_INTEGRITY"
            rules.append(RuleIR(
                bank_id=bank_id,
                rule_id=rule_id,
                rule_name=rule_name,
                description=f"Extracted from SQL: {trimmed[:200]}",
                category=category,
                source_type="EXISTING_DOCUMENT",
                condition_tree=ConditionTree(operator="AND", conditions=conditions),
                actions=[ActionNode(action_type="FLAG_REVIEW", target="database_record")],
                traceability={
                    "filename": filename,
                    "statement_index": idx + 1,
                    "raw_sql": trimmed[:500],
                },
                raw_content=trimmed,
            ))
        if rules:
            return rules

    # 3. Text / Markdown / Unstructured Policy Rule Extraction
    # Split by paragraphs or numbered rules
    sections = re.split(r"\n(?=(?:[0-9]+\.|\bSection\b|\bRule\b|\bClause\b))", content)
    if len(sections) <= 1:
        sections = content.split("\n\n")

    for idx, sec in enumerate(sections):
        trimmed = sec.strip()
        if not trimmed or len(trimmed) < 20:
            continue
        
        rule_num = idx + 1
        title_line = trimmed.split("\n")[0][:100]
        category = "GENERAL"
        lower_sec = trimmed.lower()
        if any(w in lower_sec for w in ["aml", "anti-money", "laundering", "smurfing", "suspicious"]):
            category = "AML"
        elif any(w in lower_sec for w in ["kyc", "customer identification", "cdd", "due diligence"]):
            category = "KYC"
        elif any(w in lower_sec for w in ["capital", "car", "crar", "basel", "tier 1", "tier 2"]):
            category = "CAPITAL_ADEQUACY"
        elif any(w in lower_sec for w in ["loan", "credit", "ltv", "lending", "mortgage", "npa"]):
            category = "LENDING"
        elif any(w in lower_sec for w in ["forex", "fema", "cross-border", "swift", "foreign exchange"]):
            category = "FOREIGN_EXCHANGE"
        elif any(w in lower_sec for w in ["sanction", "ofac", "unsc", "pep", "politically exposed"]):
            category = "SANCTIONS"

        # Heuristic threshold extraction
        conditions = []
        amount_match = re.search(r"(?:rs\.?|inr|\$|usd)\s*([0-9,]+(?:\.[0-9]+)?)", trimmed, re.IGNORECASE)
        if not amount_match:
            amount_match = re.search(r"(?:exceeding|above|greater than|>|>=|of at least)\s*(?:rs\.?|inr|\$|usd)?\s*([0-9,]+(?:\.[0-9]+)?)", trimmed, re.IGNORECASE)
        if amount_match:
            try:
                raw_amt = amount_match.group(1).replace(",", "")
                amt = float(raw_amt)
                conditions.append(ConditionNode(
                    field="transaction_amount",
                    operator="gte",
                    value=amt,
                    value_type="numeric",
                    unit="INR" if "inr" in lower_sec or "rs" in lower_sec else "CURRENCY",
                ))
            except ValueError:
                pass

        days_match = re.search(r"within\s*([0-9]+)\s*(?:days|business days|months)", trimmed, re.IGNORECASE)
        if days_match:
            try:
                days = int(days_match.group(1))
                conditions.append(ConditionNode(
                    field="retention_days",
                    operator="lte",
                    value=days,
                    value_type="numeric",
                    unit="DAYS",
                ))
            except ValueError:
                pass

        actions = [ActionNode(action_type="FLAG_REVIEW", target="transaction")]
        if any(w in lower_sec for w in ["block", "freeze", "decline", "reject"]):
            actions = [ActionNode(action_type="BLOCK", target="transaction")]
        elif any(w in lower_sec for w in ["second review", "dual approval", "maker-checker", "two officer"]):
            actions = [ActionNode(action_type="SECOND_REVIEW", target="transaction")]
        elif any(w in lower_sec for w in ["escalate", "str", "suspicious transaction report", "fiu"]):
            actions = [ActionNode(action_type="ESCALATE", target="fiu_reporting")]

        rules.append(RuleIR(
            bank_id=bank_id,
            rule_id=f"BANK-RULE-{category[:3]}-{rule_num:03d}",
            rule_name=title_line.lstrip("0123456789. -#*"),
            description=trimmed,
            category=category,
            source_type="EXISTING_DOCUMENT",
            condition_tree=ConditionTree(operator="AND", conditions=conditions),
            actions=actions,
            traceability={
                "filename": filename,
                "section_index": rule_num,
                "excerpt": trimmed[:300],
            },
            raw_content=trimmed,
        ))

    if not rules:
        raise ValueError(f"Extraction failed: no compliance rules could be extracted from '{filename}'.")

    return rules


def extract_obligations_from_circular(
    circular_text: str,
    circular_number: str,
    authority: str = "RBI",
    filename: str = "circular.pdf",
    bank_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """
    Extracts structured regulatory obligations and candidate Rule IR representations
    from newly uploaded regulatory circulars.
    """
    obligations: list[dict[str, Any]] = []
    
    # Split text by sections, clauses, or paragraph chunks
    raw_clauses = re.split(r"\n\s*(?=(?:(?:Clause|Section|Para|Paragraph|\b\d+\.))\s*)", circular_text)
    if len(raw_clauses) <= 1:
        raw_clauses = [c.strip() for c in circular_text.split("\n\n") if len(c.strip()) > 20]

    for idx, clause in enumerate(raw_clauses):
        trimmed = clause.strip()
        if len(trimmed) < 20:
            continue
            
        clause_id = f"CL-{idx + 1:02d}"
        clause_match = re.search(r"(?:Clause|Section|Para|Paragraph)\s*([0-9]+(?:\.[0-9]+)*)", trimmed, re.IGNORECASE)
        if clause_match:
            clause_id = f"CL-{clause_match.group(1)}"
            
        lower_clause = trimmed.lower()
        category = "GENERAL"
        if any(w in lower_clause for w in ["aml", "anti-money", "laundering", "smurfing", "suspicious"]):
            category = "AML"
        elif any(w in lower_clause for w in ["kyc", "customer identification", "due diligence", "beneficial owner"]):
            category = "KYC"
        elif any(w in lower_clause for w in ["capital", "car", "crar", "basel", "tier 1", "tier 2"]):
            category = "CAPITAL_ADEQUACY"
        elif any(w in lower_clause for w in ["loan", "credit", "ltv", "lending", "mortgage", "priority sector"]):
            category = "LENDING"
        elif any(w in lower_clause for w in ["forex", "fema", "cross-border", "swift", "foreign exchange", "nostro"]):
            category = "FOREIGN_EXCHANGE"
        elif any(w in lower_clause for w in ["sanction", "ofac", "unsc", "pep"]):
            category = "SANCTIONS"
        elif any(w in lower_clause for w in ["cyber", "it governance", "data protection", "outsource", "cloud"]):
            category = "IT_AND_CYBER_SECURITY"

        is_mandatory = any(w in lower_clause for w in ["shall", "must", "mandatory", "required to", "strictly comply"])
        
        # Effective date extraction
        date_match = re.search(r"(?:with effect from|effective(?: from)?|w\.e\.f\.?|by|deadline:?)\s*([0-9]{1,2}[-\s/][a-zA-Z0-9]+[-\s/][0-9]{2,4})", trimmed, re.IGNORECASE)
        effective_date = date_match.group(1) if date_match else None

        # Threshold extraction
        conditions = []
        amount_match = re.search(r"(?:rs\.?|inr|\$|usd)\s*([0-9,]+(?:\.[0-9]+)?)", trimmed, re.IGNORECASE)
        if not amount_match:
            amount_match = re.search(r"(?:exceeding|above|greater than|>|>=|of at least)\s*(?:rs\.?|inr|\$|usd)?\s*([0-9,]+(?:\.[0-9]+)?)", trimmed, re.IGNORECASE)
        if amount_match:
            try:
                amt = float(amount_match.group(1).replace(",", ""))
                conditions.append(ConditionNode(
                    field="transaction_amount",
                    operator="gte",
                    value=amt,
                    value_type="numeric",
                    unit="INR" if "inr" in lower_clause or "rs" in lower_clause else "CURRENCY",
                ))
            except ValueError:
                pass

        days_match = re.search(r"within\s*([0-9]+)\s*(?:days|business days|months)", trimmed, re.IGNORECASE)
        if days_match:
            try:
                days = int(days_match.group(1))
                conditions.append(ConditionNode(
                    field="reporting_deadline_days",
                    operator="lte",
                    value=days,
                    value_type="numeric",
                    unit="DAYS",
                ))
            except ValueError:
                pass

        action_type = "FLAG_REVIEW"
        if any(w in lower_clause for w in ["block", "freeze", "stop", "prohibit"]):
            action_type = "BLOCK"
        elif any(w in lower_clause for w in ["report to", "fiu", "str", "escalate", "intimate"]):
            action_type = "ESCALATE"
        elif any(w in lower_clause for w in ["require document", "proof", "verify", "collect id"]):
            action_type = "REQUIRE_DOCUMENTATION"

        # Construct Candidate Rule IR
        candidate_rule = RuleIR(
            bank_id=bank_id,
            rule_id=f"REG-{category[:3]}-{clause_id.replace('.', '-')}",
            rule_name=f"Mandate {clause_id}: {trimmed[:60]}...",
            description=trimmed,
            category=category,
            source_type="REGULATORY_CIRCULAR",
            condition_tree=ConditionTree(operator="AND", conditions=conditions),
            actions=[ActionNode(action_type=action_type, target="transaction")],
            traceability={
                "circular_number": circular_number,
                "authority": authority,
                "clause_id": clause_id,
                "filename": filename,
                "raw_text": trimmed[:400],
            },
            raw_content=trimmed,
        )

        obligations.append({
            "obligation_id": f"OBL-{circular_number}-{clause_id}",
            "clause_id": clause_id,
            "circular_number": circular_number,
            "issuing_authority": authority,
            "requirement_text": trimmed,
            "category": category,
            "is_mandatory": is_mandatory,
            "effective_date": effective_date,
            "affected_entities": ["Commercial Banks", "Payment System Operators"],
            "candidate_rule_ir": candidate_rule.model_dump(),
            "confidence": 0.95 if is_mandatory else 0.88,
        })

    return obligations
