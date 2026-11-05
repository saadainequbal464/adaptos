import re

p = ".venv/eval_plane/service.py"
src = open(p, encoding="utf-8").read()

start = src.index("def _offline_demo_expected(")
end = src.index("class AdaptOSService:")

NEW = r'''def _first_sentence(text: str, min_len: int = 40) -> str | None:
    """First sentence of at least `min_len` characters — used so the offline fixture
    citation is a verbatim span of the ACTUAL uploaded document (no task hardcoding)."""
    for s in re.split(r"(?<=[.!?])\s+", str(text or "").strip()):
        s = s.strip()
        if len(s) >= min_len:
            return s
    return None


def _evidence_sentence(usr_p: str) -> str | None:
    """Extracts the first substantive sentence from the retrieved-evidence block of a
    rendered runtime prompt, so offline responses cite the real retrieved context."""
    m = re.search(
        r"<untrusted_retrieved_evidence>(.*?)</untrusted_retrieved_evidence>",
        usr_p,
        re.DOTALL,
    )
    if not m:
        return None
    block = m.group(1)
    lines = [
        re.sub(r"^\[source_id=[^\]]+\]\s*", "", ln.strip())
        for ln in block.splitlines()
        if ln.strip().startswith("[source_id=")
    ]
    for ln in lines:
        s = _first_sentence(ln, 25)
        if s:
            return s
    return None


def _label_enum_for(output_field):
    """Infers the closed label set from an output field's description using the
    builder's own schema inference (single source of truth, no task hardcoding)."""
    try:
        from schemas import FieldSpec as _FieldSpec
        dtype = str(output_field.get("data_type", "string"))
        f = _FieldSpec(
            name=str(output_field.get("name", "out")),
            data_type="string" if dtype == "file" else dtype,
            description=str(output_field.get("description") or "Output value."),
            required=True,
        )
        schema = spec_fields_to_json_schema([f])
        enum = schema["properties"][f.name].get("enum")
        if isinstance(enum, list) and len(enum) >= 2:
            return [str(e) for e in enum]
    except Exception:
        pass
    return []


def _offline_demo_label(labels, idx):
    if not labels:
        return None
    return labels[idx % len(labels)]


def _offline_demo_threshold_label(labels, user_text, context_text):
    """Generic threshold rule for chat without a live model: if the user message
    contains a number greater than the largest number found in the application's
    constraint/evidence context, pick the last label; otherwise the first.
    Works for any threshold-based decision task (refund windows, SLA hours, limits)."""
    if not labels:
        return None
    if len(labels) < 2:
        return labels[0]
    nums_user = [int(n) for n in re.findall(r"\d+", str(user_text or ""))]
    nums_ctx = [int(n) for n in re.findall(r"\d+", str(context_text or ""))]
    if nums_user and nums_ctx:
        threshold = max(nums_ctx)
        user_num = max(nums_user)
        if user_num > threshold:
            return labels[-1]
    return labels[0]


def _offline_demo_expected(
    cid: str,
    idx: int,
    dtype: str,
    field_name: str,
    labels=(),
    citation_span=None,
):
    """Shared deterministic expected-value convention between the offline case
    generator and the offline runtime handler. Fully spec-driven: labels come from
    the output schema enum, citations from the uploaded source documents."""
    if dtype == "boolean":
        return idx % 2 == 0
    if dtype in ("integer", "number"):
        return 10 + (idx % 10)
    if "citation" in field_name and citation_span:
        return citation_span
    if labels:
        return _offline_demo_label(labels, idx)
    return f"offline_demo_output_{cid}_{idx}"


def _offline_demo_input_value(dtype: str, idx: int, cid: str):
    if dtype == "integer":
        return 5 + (idx % 20)
    if dtype == "number":
        return float(5 + (idx % 20))
    if dtype == "boolean":
        return True
    return f"Requesting scenario #{idx} for {cid}: provide the requested handling."


def _offline_demo_case_responder(
    purpose: str, user_prompt: str, model_cls: Any
):
    """Generic offline fixture responder for EvalDesignerService (offline demo mode).
    Generates deterministic cases for ANY spec: labels are inferred from the output
    descriptions, citations from the actual uploaded source documents."""
    req = json.loads(user_prompt).get("untrusted_specification_data", {})
    input_fields = req.get("inputs", []) or []
    output_fields = req.get("outputs", []) or []
    out_names = [str(f.get("name")) for f in output_fields if f.get("name")]
    first_out = out_names[0] if out_names else None
    source_docs = req.get("source_documents", []) or []
    doc_text = str((source_docs[0] or {}).get("content", "")) if source_docs else ""
    citation_span = _first_sentence(doc_text)
    scenarios = ["positive", "negative", "edge_boundary", "adversarial", "graceful_failure"]
    cases = []
    for c in req.get("eligible_criteria", []):
        try:
            cid = re.sub(r"[^A-Za-z0-9_.\-]", "_", str(c["criterion_id"]))[:60] or "crit"
            method = EvaluationMethod(c["method"])
        except Exception:
            continue
        if method not in (
            EvaluationMethod.EXACT_MATCH,
            EvaluationMethod.CONTAINS,
            EvaluationMethod.SCHEMA_VALID,
        ):
            continue  # rubric-style criteria need a live judge; honest insufficient
        count = max(5, min(int(req.get("cases_per_criterion", 25)), 30))
        for i in range(1, count + 1):
            input_data = {}
            for f in input_fields:
                fname = str(f.get("name", ""))
                if not fname:
                    continue
                input_data[fname] = _offline_demo_input_value(
                    str(f.get("data_type", "string")), i, cid
                )
            target = first_out
            target_field = next(
                (f for f in output_fields if str(f.get("name")) == target), {}
            )
            labels = _label_enum_for(target_field)
            crit_desc = str(c.get("description", "") or "").lower()
            ref = {
                "reference_kind": "deterministic",
                "reference_status": "available",
            }
            if method == EvaluationMethod.EXACT_MATCH:
                ref["expected_value"] = _offline_demo_expected(
                    cid,
                    i,
                    str(target_field.get("data_type", "string")),
                    target or "",
                    labels,
                    citation_span,
                )
                m_cfg = {
                    "method": "exact_match",
                    "target_output_field": target,
                    "case_sensitive": True,
                    "strip_whitespace": True,
                }
            elif method == EvaluationMethod.CONTAINS:
                if citation_span and ("citation" in (target or "").lower() or "cit" in crit_desc):
                    sub = citation_span
                else:
                    sub = _offline_demo_expected(cid, i, "string", target or "", labels, None)
                ref["required_substrings"] = [sub]
                m_cfg = {
                    "method": "contains",
                    "target_output_field": target,
                    "match_mode": "substring",
                    "case_sensitive": False,
                }
            else:
                m_cfg = {
                    "method": "schema_valid",
                    "json_schema": {
                        "type": "object",
                        "properties": {
                            f.get("name"): {"type": str(f.get("data_type", "string"))}
                            for f in output_fields
                            if f.get("name")
                        },
                        "required": out_names,
                    },
                }
            cases.append({
                "case_id": f"case_{cid}_{i:02d}",
                "criterion_id": cid,
                "scenario_type": scenarios[(i - 1) % len(scenarios)],
                "description": f"Offline deterministic scenario {i} for {cid}.",
                "input_data": input_data,
                "method": method.value if hasattr(method, "value") else str(method),
                "method_config": m_cfg,
                "reference": ref,
                "source_document_ids": [],
                "rationale": "Offline deterministic fixture case.",
            })
    return {"cases": cases}


def _offline_demo_runtime_handler(
    sys_p: str, usr_p: str, schema: dict
):
    """Offline deterministic runtime handler for Builder/evaluation model.chat calls.
    Fully spec-driven: labels come from the output schema enum, citations from the
    retrieved-evidence block of the rendered prompt."""
    props = schema.get("properties") or {}
    out_names = list(props.keys())
    m = re.search(r"#(\d+)\s+for\s+([A-Za-z0-9_.\-]+)", usr_p)
    idx = int(m.group(1)) if m else 1
    cid = m.group(2) if m else "crit"
    citation = _evidence_sentence(usr_p)
    payload = {}
    for k in out_names:
        prop = props.get(k) or {}
        vtype = str(prop.get("type"))
        labels = [str(e) for e in prop.get("enum", [])] if prop.get("enum") else []
        if vtype == "boolean":
            payload[k] = idx % 2 == 0
        elif vtype in ("integer", "number"):
            payload[k] = 10 + (idx % 10)
        elif vtype == "string" and "citation" in k and citation:
            payload[k] = citation
        elif vtype == "string" and labels:
            payload[k] = _offline_demo_label(labels, idx)
        elif vtype == "string":
            payload[k] = _offline_demo_expected(cid, idx, "string", k)
        else:
            payload[k] = None
    return payload


class _OfflineDemoMuseTransport:
    """Deterministic Muse transport for the offline demo Runtime chat. Answers are
    derived from the application's own output schema (enum labels) and the retrieved
    evidence in the prompt — generic for any task, no hardcoded decisions."""

    def create_chat_completion(
        self,
        *,
        base_url: str,
        api_key: str,
        payload: dict,
        timeout_seconds: float,
    ):
        msgs = payload.get("messages", [])
        last_user = next(
            (m.get("content", "") for m in reversed(msgs) if m.get("role") == "user"), ""
        )
        context_text = "\n".join(
            m.get("content", "") for m in msgs if m.get("role") != "user"
        ) or last_user
        schema = (
            (payload.get("response_format") or {}).get("json_schema") or {}
        ).get("schema") or {}
        props = schema.get("properties") or {}
        evidence = _evidence_sentence(last_user)
        out = {}
        for k, v in props.items():
            vtype = str(v.get("type"))
            labels = [str(e) for e in v.get("enum", [])] if v.get("enum") else []
            if vtype == "boolean":
                out[k] = True
            elif vtype in ("integer", "number"):
                m_num = re.search(r"\d+", last_user)
                out[k] = int(m_num.group(0)) if m_num else 0
            elif vtype == "string" and "citation" in k and evidence:
                out[k] = evidence
            elif vtype == "string" and labels:
                out[k] = _offline_demo_threshold_label(labels, last_user, context_text)
            elif vtype == "string":
                out[k] = evidence or "offline_demo_response"
            else:
                out[k] = None
        return {
            "choices": [
                {"message": {"role": "assistant", "content": json.dumps(out)}}
            ]
        }


'''

src = src[:start] + NEW + src[end:]
open(p, "w", encoding="utf-8").write(src)
print("fixture trio generalized OK")
