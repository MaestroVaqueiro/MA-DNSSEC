import csv
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path


def load_jsonl(path):
    rows = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL {path}:{line_number}: {exc}") from exc
    return rows


# Keeps EDNS options in their observed wire order.
def option_tuples(value):
    if value in (None, "", []):
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return [(value, "", None, "")]
    if not isinstance(value, list):
        return [(str(value), "", None, "")]
    result = []
    for option in value:
        if isinstance(option, dict):
            result.append(
                (
                    option.get("code", option.get("Code")),
                    option.get("name", option.get("type", "")),
                    option.get("length"),
                    option.get("data_sha256") or option.get("data_hex") or "",
                )
            )
        else:
            result.append((str(option), "", None, ""))
    return result


def list_str(value):
    values = option_tuples(value)
    if not values:
        return "none"
    parts = []
    for code, name, length, payload_id in values:
        part = f"{code}:{name}:{length}"
        if payload_id:
            part += f":sha256={str(payload_id)[:12]}"
        parts.append(part)
    return ",".join(parts)


def option_by_code(value, code):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return {}
    for option in value or []:
        if not isinstance(option, dict):
            continue
        try:
            if int(option.get("code", option.get("Code"))) == int(code):
                return option
        except (TypeError, ValueError):
            continue
    return {}


def qname_metrics(name):
    value = str(name or "")
    fqdn = value if value.endswith(".") else value + "."
    trimmed = fqdn[:-1]
    labels = trimmed.split(".") if trimmed else []
    return {
        "text_length": len(trimmed),
        "wire_length": 1 + sum(1 + len(label.encode("ascii", errors="ignore")) for label in labels),
        "label_count": len(labels),
        "max_label_length": max((len(label.encode("ascii", errors="ignore")) for label in labels), default=0),
        "has_uppercase": any(char.isupper() for char in trimmed),
    }


def first_label_entropy(name):
    first = str(name or "").rstrip(".").split(".", 1)[0]
    if not first:
        return 0.0
    counts = Counter(first.lower())
    total = len(first)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def primary_key(row):
    return (row.get("experiment_id"), str(row.get("repetition", "")))


def qtype_equal(row):
    observed = row.get("qtype_numeric")
    client = row.get("client_qtype_numeric")
    if observed is not None and client is not None:
        try:
            return int(observed) == int(client)
        except (TypeError, ValueError):
            pass
    return str(row.get("qtype", "")).upper() == str(row.get("client_qtype", "")).upper()


def is_primary(row):
    return (
        str(row.get("qname", "")).lower() == str(row.get("client_qname", "")).lower()
        and qtype_equal(row)
    )


def classify_primary_role(row, state):
    key = primary_key(row)
    transport = str(row.get("transport", "")).lower()
    previous_tc = state.get(key, False)
    if key not in state:
        state[key] = transport == "udp" and row.get("response_tc") is True
        return "primary_query"
    if previous_tc and transport == "tcp":
        state[key] = False
        return "primary_tcp_fallback"
    state[key] = transport == "udp" and row.get("response_tc") is True
    return "primary_retransmission"


def annotate_auth(auth_rows):
    state = {}
    for row in auth_rows:
        persisted = str(row.get("upstream_role") or "")
        row["_primary_role"] = persisted if persisted.startswith("primary_") else (classify_primary_role(row, state) if is_primary(row) else "")


def make_primary_index(auth_rows):
    annotate_auth(auth_rows)
    index = defaultdict(list)
    for row in auth_rows:
        if is_primary(row):
            index[primary_key(row)].append(row)
    return index


def first_primary(client_row, index):
    rows = index.get(primary_key(client_row), [])
    for row in rows:
        if row.get("_primary_role") == "primary_query":
            return row
    return rows[0] if rows else None


def role_for_nonprimary(row):
    persisted = str(row.get("upstream_role") or "")
    if persisted and not persisted.startswith("primary_"):
        return persisted
    qtype = str(row.get("qtype", "")).upper()
    qname = str(row.get("qname", "")).lower()
    client_qtype = str(row.get("client_qtype", "")).upper()
    client_qname = str(row.get("client_qname", "")).lower()

    if qname.startswith("_ta-"):
        return "trust_anchor_signal"
    if qtype == "A" and qname == client_qname and client_qtype != "A":
        return "same_name_A_followup"
    if qtype in {"DNSKEY", "DS"}:
        return "auxiliary_dnssec"
    if qtype in {"A", "AAAA"} and qname != client_qname:
        return "synthesized_address_lookup"
    if qtype == "NS" and qname != client_qname:
        return "auxiliary_delegation"
    return "other_auxiliary"


FEATURES = [
    "message_id_same",
    "qname_semantic_same",
    "qname_exact_same",
    "qtype_same",
    "qclass_same",
    "qr_same",
    "aa_same",
    "tc_same",
    "rd_same",
    "ra_same",
    "z_same",
    "ad_same",
    "cd_same",
    "opcode_same",
    "request_rcode_same",
    "question_count_same",
    "answer_count_same",
    "authority_count_same",
    "additional_count_same",
    "edns_same",
    "do_same",
    "udp_size_same",
    "edns_version_same",
    "edns_z_flags_same",
    "edns_extended_rcode_same",
    "edns_owner_same",
    "edns_options_same",
    "tkey_present_same",
    "tkey_count_same",
    "tkey_mode_same",
    "tkey_error_same",
    "tkey_algorithm_same",
    "tkey_section_same",
    "tkey_owner_same",
    "tkey_class_same",
    "tkey_ttl_same",
    "tkey_inception_same",
    "tkey_expiration_same",
    "tkey_key_length_same",
    "tkey_other_length_same",
    "key_rr_present_same",
    "key_rr_count_same",
    "key_rr_section_same",
    "key_rr_owner_same",
    "key_rr_algorithm_same",
]


def compare_features(client, upstream):
    if upstream is None:
        return None

    client_options = option_tuples(client.get("query_edns_options"))
    upstream_options_measured = "request_edns_options" in upstream
    upstream_options = option_tuples(upstream.get("request_edns_options")) if upstream_options_measured else None

    upstream_tkey_measured = "request_tkey_present" in upstream
    client_tkey_present = client.get("query_tkey_present") is True
    upstream_tkey_present = upstream.get("request_tkey_present") is True if upstream_tkey_measured else None

    upstream_key_measured = "request_key_rr_present" in upstream
    client_key_present = client.get("query_key_rr_present") is True
    upstream_key_present = upstream.get("request_key_rr_present") is True if upstream_key_measured else None

    def present_field_same(client_field, upstream_field, client_present, upstream_present, measured):
        if not measured or not client_present or not upstream_present:
            return None
        return client.get(client_field) == upstream.get(upstream_field)

    client_qname = str(client.get("qname", ""))
    upstream_qname = str(upstream.get("qname", ""))
    comparison = {
        "message_id_same": (
            client.get("client_message_id") == upstream.get("message_id")
            if client.get("client_message_id") is not None and upstream.get("message_id") is not None
            else None
        ),
        "qname_semantic_same": client_qname.lower() == upstream_qname.lower(),
        "qname_exact_same": client_qname == upstream_qname,
        "qtype_same": (
            int(client.get("qtype_numeric")) == int(upstream.get("qtype_numeric"))
            if client.get("qtype_numeric") is not None and upstream.get("qtype_numeric") is not None
            else str(client.get("qtype", "")).upper() == str(upstream.get("qtype", "")).upper()
        ),
        "qclass_same": str(client.get("qclass", "IN")).upper() == str(upstream.get("qclass", "IN")).upper(),
        "transport_same": str(client.get("transport", "")).lower() == str(upstream.get("transport", "")).lower(),
        "qr_same": client.get("client_qr") == upstream.get("qr"),
        "aa_same": client.get("client_aa") == upstream.get("aa"),
        "tc_same": client.get("client_tc") == upstream.get("tc"),
        "rd_same": client.get("client_rd") == upstream.get("rd"),
        "ra_same": client.get("client_ra") == upstream.get("ra"),
        "z_same": client.get("client_z") == upstream.get("z"),
        "ad_same": client.get("client_ad") == upstream.get("ad"),
        "cd_same": client.get("client_cd") == upstream.get("cd"),
        "opcode_same": client.get("client_opcode") == upstream.get("opcode"),
        "request_rcode_same": client.get("client_request_rcode") == upstream.get("request_rcode"),
        "question_count_same": client.get("query_question_count") == upstream.get("request_question_count"),
        "answer_count_same": client.get("query_answer_count") == upstream.get("request_answer_count"),
        "authority_count_same": client.get("query_authority_count") == upstream.get("request_authority_count"),
        "additional_count_same": client.get("query_additional_count") == upstream.get("request_additional_count"),
        "edns_same": client.get("client_edns") == upstream.get("edns_present"),
        "do_same": client.get("client_do") == upstream.get("do"),
        "udp_size_same": client.get("client_udp_payload_size") == upstream.get("udp_payload_size"),
        "edns_version_same": client.get("client_edns_version") == upstream.get("edns_version"),
        "edns_z_flags_same": client.get("client_edns_z_flags") == upstream.get("edns_z_flags"),
        "edns_extended_rcode_same": client.get("client_edns_extended_rcode") == upstream.get("edns_extended_rcode"),
        "edns_owner_same": str(client.get("client_edns_owner_name") or "").lower() == str(upstream.get("edns_owner_name") or "").lower(),
        "edns_options_same": client_options == upstream_options if upstream_options_measured else None,
        "tkey_present_same": client_tkey_present == upstream_tkey_present if upstream_tkey_measured else None,
        "tkey_count_same": client.get("query_tkey_count") == upstream.get("request_tkey_count") if upstream_tkey_measured else None,
        "tkey_mode_same": present_field_same("query_tkey_mode", "request_tkey_mode", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "tkey_error_same": present_field_same("query_tkey_error", "request_tkey_error", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "tkey_algorithm_same": present_field_same("query_tkey_algorithm", "request_tkey_algorithm", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "tkey_section_same": present_field_same("query_tkey_section", "request_tkey_section", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "tkey_owner_same": (
            str(client.get("query_tkey_owner") or "").lower() == str(upstream.get("request_tkey_owner") or "").lower()
            if upstream_tkey_measured and client_tkey_present and upstream_tkey_present else None
        ),
        "tkey_class_same": (
            str(client.get("query_tkey_class") or "").upper() == str(upstream.get("request_tkey_class") or "").upper()
            if upstream_tkey_measured and client_tkey_present and upstream_tkey_present else None
        ),
        "tkey_ttl_same": present_field_same("query_tkey_ttl", "request_tkey_ttl", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "tkey_inception_same": present_field_same("query_tkey_inception", "request_tkey_inception", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "tkey_expiration_same": present_field_same("query_tkey_expiration", "request_tkey_expiration", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "tkey_key_length_same": present_field_same("query_tkey_key_length", "request_tkey_key_length", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "tkey_other_length_same": present_field_same("query_tkey_other_length", "request_tkey_other_length", client_tkey_present, upstream_tkey_present, upstream_tkey_measured),
        "key_rr_present_same": client_key_present == upstream_key_present if upstream_key_measured else None,
        "key_rr_count_same": client.get("query_key_rr_count") == upstream.get("request_key_rr_count") if upstream_key_measured else None,
        "key_rr_section_same": present_field_same("query_key_rr_section", "request_key_rr_section", client_key_present, upstream_key_present, upstream_key_measured),
        "key_rr_owner_same": (
            str(client.get("query_key_rr_owner") or "").lower() == str(upstream.get("request_key_rr_owner") or "").lower()
            if upstream_key_measured and client_key_present and upstream_key_present else None
        ),
        "key_rr_algorithm_same": present_field_same("query_key_rr_algorithm", "request_key_rr_algorithm", client_key_present, upstream_key_present, upstream_key_measured),
    }
    return comparison


# Excludes transport because the client and upstream exchanges use separate connections.
def all_measured_features_same(comparison):
    if comparison is None:
        return ""
    values = [comparison[field] for field in FEATURES if comparison.get(field) is not None]
    return all(values) if values else ""


def build_records(mode, client_rows, auth_rows):
    index = make_primary_index(auth_rows)
    auth_by_experiment = defaultdict(list)
    for row in auth_rows:
        auth_by_experiment[primary_key(row)].append(row)

    records = []
    for client in client_rows:
        key = primary_key(client)
        primaries = index.get(key, [])
        first = first_primary(client, index)
        comparison = compare_features(client, first)
        auxiliary = Counter(
            role_for_nonprimary(row)
            for row in auth_by_experiment.get(key, [])
            if not is_primary(row)
        )

        client_private_option = option_by_code(client.get("query_edns_options"), 65001)
        upstream_private_option = (
            option_by_code(first.get("request_edns_options"), 65001)
            if first and "request_edns_options" in first
            else {}
        )
        client_private_digest = str(client_private_option.get("data_sha256") or "")
        upstream_private_digest = str(upstream_private_option.get("data_sha256") or "")

        record = {
            "mode": mode,
            "run_id": client.get("run_id"),
            "resolver": client.get("resolver"),
            "experiment_id": client.get("experiment_id"),
            "repetition": client.get("repetition"),
            "case_id": client.get("case_id"),
            "family": client.get("family"),
            "research_dimension": client.get("research_dimension"),
            "comparison_group": client.get("comparison_group"),
            "test_tier": client.get("test_tier"),
            "reference_case_id": client.get("reference_case_id"),
            "changed_properties": ", ".join(str(value) for value in (client.get("changed_properties") or [])),
            "variant_id": client.get("variant_id"),
            "variant_description": client.get("variant_description"),
            "expected_validity": client.get("expected_validity"),
            "expected_processing": client.get("expected_processing"),
            "core_analysis_eligible": not (client.get("expected_observations") or {}).get("exclude_from_core_analysis", False),
            "client_message_id": client.get("client_message_id"),
            "client_qname": client.get("qname"),
            "client_qname_text_length": qname_metrics(client.get("qname"))["text_length"],
            "client_qname_wire_length": qname_metrics(client.get("qname"))["wire_length"],
            "client_qname_label_count": qname_metrics(client.get("qname"))["label_count"],
            "client_qname_max_label_length": qname_metrics(client.get("qname"))["max_label_length"],
            "client_qname_has_uppercase": qname_metrics(client.get("qname"))["has_uppercase"],
            "client_qname_first_label_entropy": round(first_label_entropy(client.get("qname")), 6),
            "client_qtype": client.get("qtype"),
            "client_qtype_numeric": client.get("qtype_numeric"),
            "client_qclass": client.get("qclass"),
            "client_transport": client.get("transport"),
            "client_qr": client.get("client_qr"),
            "client_aa": client.get("client_aa"),
            "client_tc": client.get("client_tc"),
            "client_rd": client.get("client_rd"),
            "client_ra": client.get("client_ra"),
            "client_z": client.get("client_z"),
            "client_ad": client.get("client_ad"),
            "client_cd": client.get("client_cd"),
            "client_opcode": client.get("client_opcode"),
            "client_request_rcode": client.get("client_request_rcode"),
            "client_question_count": client.get("query_question_count"),
            "client_answer_count": client.get("query_answer_count"),
            "client_authority_count": client.get("query_authority_count"),
            "client_additional_count": client.get("query_additional_count"),
            "client_edns": client.get("client_edns"),
            "client_do": client.get("client_do"),
            "client_udp_size": client.get("client_udp_payload_size"),
            "client_edns_version": client.get("client_edns_version"),
            "client_edns_z_flags": client.get("client_edns_z_flags"),
            "client_edns_extended_rcode": client.get("client_edns_extended_rcode"),
            "client_edns_owner_name": client.get("client_edns_owner_name"),
            "client_edns_options": list_str(client.get("query_edns_options")),
            "client_tkey_present": client.get("query_tkey_present"),
            "client_tkey_count": client.get("query_tkey_count"),
            "client_tkey_mode": client.get("query_tkey_mode"),
            "client_tkey_error": client.get("query_tkey_error"),
            "client_tkey_algorithm": client.get("query_tkey_algorithm"),
            "client_tkey_section": client.get("query_tkey_section"),
            "client_tkey_owner": client.get("query_tkey_owner"),
            "client_tkey_class": client.get("query_tkey_class"),
            "client_tkey_ttl": client.get("query_tkey_ttl"),
            "client_tkey_inception": client.get("query_tkey_inception"),
            "client_tkey_expiration": client.get("query_tkey_expiration"),
            "client_tkey_key_length": client.get("query_tkey_key_length"),
            "client_tkey_other_length": client.get("query_tkey_other_length"),
            "client_key_rr_present": client.get("query_key_rr_present"),
            "client_key_rr_count": client.get("query_key_rr_count"),
            "client_key_rr_section": client.get("query_key_rr_section"),
            "client_key_rr_owner": client.get("query_key_rr_owner"),
            "client_key_rr_algorithm": client.get("query_key_rr_algorithm"),
            "client_rcode": client.get("response_rcode"),
            "client_rcode_numeric": client.get("response_rcode_numeric"),
            "client_response_received": client.get("response_received"),
            "client_response_decode_success": client.get("response_decode_success"),
            "client_response_error_kind": client.get("error_kind"),
            "client_response_wire_size": client.get("response_wire_size"),
            "client_response_wire_sha256": client.get("response_wire_sha256"),
            "client_response_message_id": client.get("response_message_id"),
            "client_response_id_matches_query": client.get("response_id_matches_client"),
            "client_ad_response": client.get("response_ad"),
            "client_ede": client.get("response_ede_present"),
            "client_response_tkey_present": client.get("response_tkey_present"),
            "client_response_tkey_count": client.get("response_tkey_count"),
            "client_response_tkey_mode": client.get("response_tkey_mode"),
            "client_response_tkey_error": client.get("response_tkey_error"),
            "client_response_tkey_algorithm": client.get("response_tkey_algorithm"),
            "client_response_tkey_section": client.get("response_tkey_section"),
            "client_response_tkey_inception": client.get("response_tkey_inception"),
            "client_response_tkey_expiration": client.get("response_tkey_expiration"),
            "local_handling_without_primary": client.get("local_handling_without_primary_upstream"),
            "local_handling_type": client.get("local_handling_type"),
            "primary_present": bool(first),
            "primary_count": len(primaries),
            "first_primary_role": first.get("_primary_role") if first else "",
            "upstream_message_id": first.get("message_id") if first else "",
            "upstream_qname": first.get("qname") if first else "",
            "upstream_qname_text_length": qname_metrics(first.get("qname"))["text_length"] if first else "",
            "upstream_qname_wire_length": qname_metrics(first.get("qname"))["wire_length"] if first else "",
            "upstream_qname_label_count": qname_metrics(first.get("qname"))["label_count"] if first else "",
            "upstream_qname_max_label_length": qname_metrics(first.get("qname"))["max_label_length"] if first else "",
            "upstream_qname_has_uppercase": qname_metrics(first.get("qname"))["has_uppercase"] if first else "",
            "upstream_qtype": first.get("qtype") if first else "",
            "upstream_qtype_numeric": first.get("qtype_numeric") if first else "",
            "upstream_qclass": first.get("qclass") if first else "",
            "upstream_transport": first.get("transport") if first else "",
            "upstream_qr": first.get("qr") if first else "",
            "upstream_aa": first.get("aa") if first else "",
            "upstream_tc": first.get("tc") if first else "",
            "upstream_rd": first.get("rd") if first else "",
            "upstream_ra": first.get("ra") if first else "",
            "upstream_z": first.get("z") if first else "",
            "upstream_ad": first.get("ad") if first else "",
            "upstream_cd": first.get("cd") if first else "",
            "upstream_opcode": first.get("opcode") if first else "",
            "upstream_request_rcode": first.get("request_rcode") if first else "",
            "upstream_question_count": first.get("request_question_count") if first else "",
            "upstream_answer_count": first.get("request_answer_count") if first else "",
            "upstream_authority_count": first.get("request_authority_count") if first else "",
            "upstream_additional_count": first.get("request_additional_count") if first else "",
            "upstream_edns": first.get("edns_present") if first else "",
            "upstream_do": first.get("do") if first else "",
            "upstream_udp_size": first.get("udp_payload_size") if first else "",
            "upstream_edns_version": first.get("edns_version") if first else "",
            "upstream_edns_z_flags": first.get("edns_z_flags") if first else "",
            "upstream_edns_extended_rcode": first.get("edns_extended_rcode") if first else "",
            "upstream_edns_owner_name": first.get("edns_owner_name") if first else "",
            "upstream_edns_options": list_str(first.get("request_edns_options")) if first and "request_edns_options" in first else "not_measured",
            "client_private_edns_present": bool(client_private_option),
            "client_private_edns_length": client_private_option.get("length", ""),
            "client_private_edns_sha256": client_private_digest,
            "client_private_edns_utf8_valid": client_private_option.get("utf8_valid", ""),
            "client_private_edns_printable": client_private_option.get("printable_utf8", ""),
            "client_private_edns_text": client_private_option.get("utf8_text", ""),
            "upstream_private_edns_present": bool(upstream_private_option) if first else "",
            "upstream_private_edns_length": upstream_private_option.get("length", ""),
            "upstream_private_edns_sha256": upstream_private_digest,
            "private_edns_payload_same": (
                client_private_digest == upstream_private_digest
                if client_private_digest and upstream_private_digest
                else ""
            ),
            "upstream_tkey_present": first.get("request_tkey_present") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_count": first.get("request_tkey_count") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_mode": first.get("request_tkey_mode") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_error": first.get("request_tkey_error") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_algorithm": first.get("request_tkey_algorithm") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_section": first.get("request_tkey_section") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_owner": first.get("request_tkey_owner") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_class": first.get("request_tkey_class") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_ttl": first.get("request_tkey_ttl") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_inception": first.get("request_tkey_inception") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_expiration": first.get("request_tkey_expiration") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_key_length": first.get("request_tkey_key_length") if first and "request_tkey_present" in first else "not_measured",
            "upstream_tkey_other_length": first.get("request_tkey_other_length") if first and "request_tkey_present" in first else "not_measured",
            "upstream_key_rr_present": first.get("request_key_rr_present") if first and "request_key_rr_present" in first else "not_measured",
            "upstream_key_rr_count": first.get("request_key_rr_count") if first and "request_key_rr_present" in first else "not_measured",
            "upstream_key_rr_section": first.get("request_key_rr_section") if first and "request_key_rr_present" in first else "not_measured",
            "upstream_key_rr_owner": first.get("request_key_rr_owner") if first and "request_key_rr_present" in first else "not_measured",
            "upstream_key_rr_algorithm": first.get("request_key_rr_algorithm") if first and "request_key_rr_present" in first else "not_measured",
            "upstream_response_rcode": first.get("response_rcode") if first else "",
            "upstream_request_wire_size": first.get("request_wire_size") if first else "",
            "auxiliary_dnssec": auxiliary["auxiliary_dnssec"],
            "synthesized_address_lookup": auxiliary["synthesized_address_lookup"],
            "same_name_A_followup": auxiliary["same_name_A_followup"],
            "trust_anchor_signal": auxiliary["trust_anchor_signal"],
            "auxiliary_delegation": auxiliary["auxiliary_delegation"],
            "other_auxiliary": auxiliary["other_auxiliary"],
        }

        if comparison is None:
            for feature in FEATURES + ["transport_same"]:
                record[feature] = ""
            record["all_measured_query_features_same"] = ""
        else:
            for feature in FEATURES + ["transport_same"]:
                record[feature] = comparison.get(feature)
            record["all_measured_query_features_same"] = all_measured_features_same(comparison)

        records.append(record)
    return records


HEADER_FEATURES = {
    "header_qr1": ("QR", "client_qr", "upstream_qr", "qr_same"),
    "header_opcode_update": ("Opcode", "client_opcode", "upstream_opcode", "opcode_same"),
    "header_opcode_15": ("Opcode", "client_opcode", "upstream_opcode", "opcode_same"),
    "header_aa1": ("AA", "client_aa", "upstream_aa", "aa_same"),
    "header_tc1": ("TC", "client_tc", "upstream_tc", "tc_same"),
    "header_rd0": ("RD", "client_rd", "upstream_rd", "rd_same"),
    "header_ra1": ("RA", "client_ra", "upstream_ra", "ra_same"),
    "header_z1": ("Z", "client_z", "upstream_z", "z_same"),
    "header_ad1": ("AD", "client_ad", "upstream_ad", "ad_same"),
    "header_cd1": ("CD", "client_cd", "upstream_cd", "cd_same"),
    "header_request_rcode1": ("Request-RCODE", "client_request_rcode", "upstream_request_rcode", "request_rcode_same"),
}


EDNS_CORE_FEATURES = {
    "edns_absent": ("EDNS", "client_edns", "upstream_edns", "edns_same"),
    "edns_version_1": ("EDNS-Version", "client_edns_version", "upstream_edns_version", "edns_version_same"),
    "edns_do0": ("DO", "client_do", "upstream_do", "do_same"),
    "edns_udp_512": ("UDP-Größe", "client_udp_size", "upstream_udp_size", "udp_size_same"),
    "edns_udp_1400": ("UDP-Größe", "client_udp_size", "upstream_udp_size", "udp_size_same"),
    "edns_udp_4096": ("UDP-Größe", "client_udp_size", "upstream_udp_size", "udp_size_same"),
    "edns_udp_0": ("UDP-Größe", "client_udp_size", "upstream_udp_size", "udp_size_same"),
    "edns_unknown_z_flag": ("EDNS-Z-Flags", "client_edns_z_flags", "upstream_edns_z_flags", "edns_z_flags_same"),
    "edns_extended_rcode": ("EDNS Extended RCODE", "client_edns_extended_rcode", "upstream_edns_extended_rcode", "edns_extended_rcode_same"),
    "edns_nonroot_owner": ("OPT-Owner", "client_edns_owner_name", "upstream_edns_owner_name", "edns_owner_same"),
    "edns_two_opt": ("Additional/OPT-Anzahl", "client_additional_count", "upstream_additional_count", "additional_count_same"),
}


SECTION_FEATURES = {
    "section_qdcount_0": ("Question-Anzahl", "client_question_count", "upstream_question_count", "question_count_same"),
    "section_qdcount_2": ("Question-Anzahl", "client_question_count", "upstream_question_count", "question_count_same"),
    "section_qdcount_mismatch": ("Question-Anzahl", "client_question_count", "upstream_question_count", "question_count_same"),
    "section_answer_rr": ("Answer-Anzahl", "client_answer_count", "upstream_answer_count", "answer_count_same"),
    "section_authority_rr": ("Authority-Anzahl", "client_authority_count", "upstream_authority_count", "authority_count_same"),
    "section_additional_a": ("Additional-Anzahl", "client_additional_count", "upstream_additional_count", "additional_count_same"),
    "section_trailing_bytes": ("nachlaufende Bytes", "client_question_count", "upstream_question_count", "question_count_same"),
    "section_truncated_packet": ("abgeschnittene Nachricht", "client_question_count", "upstream_question_count", "question_count_same"),
}


def compact_value(value):
    if value in (None, "", "null", "not_measured"):
        return "–"
    if value is True:
        return "1"
    if value is False:
        return "0"
    text = str(value)
    if len(text) > 42:
        return text[:39] + "..."
    return text


def mutation_feature(record):
    case_id = str(record.get("case_id") or "")
    family = record.get("family")
    if case_id in HEADER_FEATURES:
        return HEADER_FEATURES[case_id]
    if case_id in EDNS_CORE_FEATURES:
        return EDNS_CORE_FEATURES[case_id]
    if case_id in SECTION_FEATURES:
        return SECTION_FEATURES[case_id]
    if family == "interaction":
        changed = {value.strip() for value in str(record.get("changed_properties") or "").split(",") if value.strip()}
        interaction_features = [
            ("flags.ad", ("AD", "client_ad", "upstream_ad", "ad_same")),
            ("flags.cd", ("CD", "client_cd", "upstream_cd", "cd_same")),
            ("edns.do", ("DO", "client_do", "upstream_do", "do_same")),
            ("edns.options", ("EDNS-Optionen", "client_edns_options", "upstream_edns_options", "edns_options_same")),
            ("edns.udp_size", ("UDP-Größe", "client_udp_size", "upstream_udp_size", "udp_size_same")),
            ("transport", ("Transport", "client_transport", "upstream_transport", "transport_same")),
            ("qtype", ("QTYPE", "client_qtype", "upstream_qtype", "qtype_same")),
        ]
        for property_name, feature in interaction_features:
            if property_name in changed:
                return feature
    if family == "qname":
        return ("QNAME", "client_qname", "upstream_qname", "qname_exact_same")
    if family == "qtype":
        return ("QTYPE", "client_qtype", "upstream_qtype", "qtype_same")
    if family == "qclass":
        return ("QCLASS", "client_qclass", "upstream_qclass", "qclass_same")
    if family == "edns_options":
        return ("EDNS-Optionen", "client_edns_options", "upstream_edns_options", "edns_options_same")
    if family == "transport":
        return ("Transport", "client_transport", "upstream_transport", "transport_same")
    return ("Baseline", "client_qtype", "upstream_qtype", "qtype_same")


def compact_outcome(record):
    rcode = str(record.get("client_rcode") or "keine Antwort")
    if not record.get("client_response_received"):
        return "Timeout; keine passende Upstream-Query"
    if not record.get("client_response_decode_success"):
        return f"{rcode}; Antwort nicht vollständig dekodierbar; keine passende Upstream-Query"
    if not record.get("primary_present"):
        return f"{rcode}; lokal verarbeitet; keine passende Upstream-Query"

    label, client_field, upstream_field, same_field = mutation_feature(record)
    count = int(record.get("primary_count") or 0)
    prefix = f"{rcode}; {count} passende Upstream-Query" + ("s" if count != 1 else "")
    same = record.get(same_field)
    if same is True:
        return f"{prefix}; {label} übernommen"
    if same is False:
        return f"{prefix}; {label} {compact_value(record.get(client_field))}→{compact_value(record.get(upstream_field))}"
    return f"{prefix}; {label} nicht vollständig messbar"


def compact_signature(record):
    label, client_field, upstream_field, same_field = mutation_feature(record)
    return (
        record.get("client_rcode"),
        bool(record.get("client_response_received")),
        bool(record.get("client_response_decode_success")),
        bool(record.get("primary_present")),
        int(record.get("primary_count") or 0),
        label,
        record.get(client_field),
        record.get(upstream_field),
        record.get(same_field),
    )


# Ignores QNAME changes deliberately introduced between repetitions.
def repetition_stability_signature(record):
    signature = list(compact_signature(record))
    changed_properties = {
        item.strip()
        for item in str(record.get("changed_properties") or "").split(",")
        if item.strip()
    }
    if "measurement_control.qname" in changed_properties:
        signature[6] = "<per-repetition-control-qname>"
        signature[7] = "<per-repetition-control-qname>"
    return tuple(signature)


def aggregate_outcome(records):
    counts = Counter(compact_outcome(record) for record in records)
    total = len(records)
    return " | ".join(f"{count}/{total}: {outcome}" for outcome, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def aggregate_signature(records):
    return tuple(sorted((repr(signature), count) for signature, count in Counter(compact_signature(record) for record in records).items()))


def human_case_rows(records):
    grouped = defaultdict(list)
    for record in records:
        grouped[record.get("case_id")].append(record)

    resolver_order = ["bind", "unbound", "powerdns"]
    mode_order = ["validating", "nonvalidating"]
    rows = []
    for case_id, case_records in sorted(grouped.items()):
        first = case_records[0]
        indexed = defaultdict(list)
        for record in case_records:
            indexed[(record["mode"], record["resolver"])].append(record)
        repetitions = min(len(indexed[(mode, resolver)]) for mode in mode_order for resolver in resolver_order)
        stable = all(
            len(Counter(repetition_stability_signature(record) for record in indexed[(mode, resolver)])) == 1
            for mode in mode_order for resolver in resolver_order
        )
        resolver_difference = any(
            len({aggregate_signature(indexed[(mode, resolver)]) for resolver in resolver_order}) > 1
            for mode in mode_order
        )
        mode_difference = any(
            aggregate_signature(indexed[("validating", resolver)]) != aggregate_signature(indexed[("nonvalidating", resolver)])
            for resolver in resolver_order
        )

        qname_wire_attribution_issue = case_id == "qname_wire_256" and any(
            not record.get("primary_present") and int(record.get("synthesized_address_lookup") or 0) > 0
            for record in case_records
        )
        if qname_wire_attribution_issue:
            statement = "Methodikprüfung: Die vorhandene Upstream-Query wird wegen Raw-Wire-QNAME derzeit falsch zugeordnet."
            lab_status = "Methodik prüfen"
        elif repetitions < 5:
            if resolver_difference and mode_difference:
                statement = "Pilot: mögliche Unterschiede zwischen Implementierungen und Validierungsmodi; Wiederholungen fehlen."
                lab_status = "Im finalen Laborlauf bestätigen"
            elif resolver_difference:
                statement = "Pilot: mögliche Unterschiede zwischen den drei Implementierungen; Wiederholungen fehlen."
                lab_status = "Im finalen Laborlauf bestätigen"
            elif mode_difference:
                statement = "Pilot: möglicher Unterschied zwischen den Validierungsmodi; Wiederholungen fehlen."
                lab_status = "Im finalen Laborlauf bestätigen"
            else:
                statement = "Pilot: bisher einheitliche Verarbeitung; Wiederholungen fehlen."
                lab_status = "Pilot bestätigt; Wiederholungen fehlen"
        elif not stable:
            statement = "Mindestens eine Laborbedingung zeigte über die Wiederholungen unterschiedliche Ergebnisse."
            lab_status = "Instabil – technisch prüfen"
        elif resolver_difference and mode_difference:
            statement = "Verarbeitung unterscheidet sich zwischen Implementierungen und Validierungsmodi."
            lab_status = "Final auswertbar"
        elif resolver_difference:
            statement = "Die drei Implementierungen verarbeiten diese Mutation unterschiedlich."
            lab_status = "Final auswertbar"
        elif mode_difference:
            statement = "Die Verarbeitung unterscheidet sich zwischen validierendem und nichtvalidierendem Modus."
            lab_status = "Final auswertbar"
        else:
            statement = "In allen sechs Laborbedingungen wurde dasselbe Ergebnis beobachtet."
            lab_status = "Final auswertbar"

        validity = str(first.get("expected_validity") or "")

        row = {
            "Fall-ID": case_id,
            "Testschicht": first.get("test_tier") or "",
            "Referenzfall": first.get("reference_case_id") or "",
            "Geänderte Eigenschaften": first.get("changed_properties") or "",
            "Familie": first.get("family") or "",
            "Mutation": first.get("variant_description") or case_id,
            "Query-Gültigkeit": validity,
            "Wiederholungen je Bedingung": repetitions,
            "Stabilität": "stabil" if stable else "abweichend",
            "Laborstatus": lab_status,
            "Kernaussage": statement,
        }
        for mode, mode_label in (("validating", "Validierend"), ("nonvalidating", "Nichtvalidierend")):
            for resolver, resolver_label in (("bind", "BIND"), ("unbound", "Unbound"), ("powerdns", "PowerDNS")):
                row[f"{mode_label} {resolver_label}"] = aggregate_outcome(indexed[(mode, resolver)])
        row.update({
            "Resolverunterschied": "ja" if resolver_difference else "nein",
            "Modusunterschied": "ja" if mode_difference else "nein",
        })
        rows.append(row)
    return rows


def write_case_overview(output_dir, records):
    rows = human_case_rows(records)
    path = output_dir / "main_case_overview.csv"
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), delimiter=";")
        writer.writeheader()
        writer.writerows(rows)
    return path


def main():
    if len(sys.argv) != 6:
        raise SystemExit(
            "usage: python3 scripts/compare_results.py "
            "VALID_CLIENT_LOG VALID_AUTH_LOG "
            "NONVALID_CLIENT_LOG NONVALID_AUTH_LOG OUTPUT_DIR"
        )

    valid_client, valid_auth, nonvalid_client, nonvalid_auth, output_dir = sys.argv[1:]
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    records = []
    records.extend(build_records("validating", load_jsonl(valid_client), load_jsonl(valid_auth)))
    records.extend(build_records("nonvalidating", load_jsonl(nonvalid_client), load_jsonl(nonvalid_auth)))
    if not records:
        raise ValueError("no client records loaded")

    event_path = output_dir / "main_processed_events.csv"
    with event_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)

    case_path = write_case_overview(output_dir, records)
    print("wrote", event_path)
    print("wrote", case_path)


if __name__ == "__main__":
    main()
