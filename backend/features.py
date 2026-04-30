from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List


MODEL_FEATURE_FIELDS = [
    "FlowDuration",
    "BwdPacketLenMax",
    "BwdPacketLenMin",
    "BwdPacketLenMean",
    "BwdPacketLenStd",
    "FlowIATMean",
    "FlowIATStd",
    "FlowIATMax",
    "FlowIATMin",
    "FwdIATTotal",
    "FwdIATMean",
    "FwdIATStd",
    "FwdIATMax",
    "FwdIATMin",
    "BwdIATTotal",
    "BwdIATMean",
    "BwdIATStd",
    "BwdIATMax",
    "BwdIATMin",
    "FwdPSHFlags",
    "FwdPackets_s",
    "MaxPacketLen",
    "PacketLenMean",
    "PacketLenStd",
    "PacketLenVar",
    "FINFlagCount",
    "SYNFlagCount",
    "PSHFlagCount",
    "ACKFlagCount",
    "URGFlagCount",
    "AvgPacketSize",
    "AvgBwdSegmentSize",
    "InitWinBytesFwd",
    "InitWinBytesBwd",
    "ActiveMin",
    "IdleMean",
    "IdleStd",
    "IdleMax",
    "IdleMin",
]

FLOW_METADATA_FIELDS = [
    "Src",
    "SrcPort",
    "Dest",
    "DestPort",
    "Protocol",
    "FlowStartTime",
    "FlowLastSeen",
    "PName",
    "PID",
]

ALERT_FIELDS = ["FlowID"] + MODEL_FEATURE_FIELDS + FLOW_METADATA_FIELDS + ["Classification", "Probability", "Risk"]

AE_FEATURES = [
    "FlowDuration",
    "BwdPacketLengthMax",
    "BwdPacketLengthMin",
    "BwdPacketLengthMean",
    "BwdPacketLengthStd",
    "FlowIATMean",
    "FlowIATStd",
    "FlowIATMax",
    "FlowIATMin",
    "FwdIATTotal",
    "FwdIATMean",
    "FwdIATStd",
    "FwdIATMax",
    "FwdIATMin",
    "BwdIATTotal",
    "BwdIATMean",
    "BwdIATStd",
    "BwdIATMax",
    "BwdIATMin",
    "FwdPSHFlags",
    "FwdPackets/s",
    "PacketLengthMax",
    "PacketLengthMean",
    "PacketLengthStd",
    "PacketLengthVariance",
    "FINFlagCount",
    "SYNFlagCount",
    "PSHFlagCount",
    "ACKFlagCount",
    "URGFlagCount",
    "AveragePacketSize",
    "BwdSegmentSizeAvg",
    "FWDInitWinBytes",
    "BwdInitWinBytes",
    "ActiveMin",
    "IdleMean",
    "IdleStd",
    "IdleMax",
    "IdleMin",
]

DISPLAY_LABELS = {
    "FlowID": "Mã flow",
    "Src": "Nguồn",
    "SrcPort": "Cổng nguồn",
    "Dest": "Đích",
    "DestPort": "Cổng đích",
    "Protocol": "Giao thức",
    "FlowStartTime": "Bắt đầu",
    "FlowLastSeen": "Lần cuối thấy",
    "PName": "Ứng dụng",
    "PID": "PID",
    "Classification": "Dự đoán",
    "Probability": "Xác suất",
    "Risk": "Rủi ro",
}

PREDICTION_LABELS = {
    "Benign": "Lưu lượng hợp lệ",
    "Botnet": "Lưu lượng botnet",
    "DDoS": "Tấn công DDoS",
    "DoS": "Tấn công DoS",
    "FTP-Patator": "Tấn công dò quét FTP",
    "Probe": "Dò quét thăm dò",
    "RDP-Patator": "Tấn công dò quét RDP",
    "SMB-Patator": "Tấn công dò quét SMB",
    "SSH-Patator": "Tấn công dò quét SSH",
    "SMTP-Patator": "Tấn công dò quét SMTP",
    "Telnet-Patator": "Tấn công dò quét Telnet",
    "Web Attack": "Tấn công ứng dụng web",
}

# Visible alert categories in the dashboard filter.
DEMO_FILTER_PREDICTION_KEYS = [
    "Benign",
    "DDoS",
    "DoS",
    "FTP-Patator",
    "Probe",
    "RDP-Patator",
    "SMB-Patator",
    "SSH-Patator",
    "SMTP-Patator",
    "Telnet-Patator",
]

PREDICTION_ALIASES = {
    "Luu luong hop le": "Lưu lượng hợp lệ",
    "LÆ°u lÆ°á»£ng há»£p lá»‡": "Lưu lượng hợp lệ",
    "Luu luong botnet": "Lưu lượng botnet",
    "LÆ°u lÆ°á»£ng botnet": "Lưu lượng botnet",
    "Tan cong DDoS": "Tấn công DDoS",
    "Táº¥n cÃ´ng DDoS": "Tấn công DDoS",
    "Tan cong DoS": "Tấn công DoS",
    "Táº¥n cÃ´ng DoS": "Tấn công DoS",
    "Tan cong do quet FTP": "Tấn công dò quét FTP",
    "Táº¥n cÃ´ng dÃ² quÃ©t FTP": "Tấn công dò quét FTP",
    "Do quet tham do": "Dò quét thăm dò",
    "DÃ² quÃ©t thÄƒm dÃ²": "Dò quét thăm dò",
    "Tan cong do quet RDP": "Tấn công dò quét RDP",
    "Tan cong do quet SMB": "Tấn công dò quét SMB",
    "Tan cong do quet SSH": "Tấn công dò quét SSH",
    "Táº¥n cÃ´ng dÃ² quÃ©t SSH": "Tấn công dò quét SSH",
    "Tan cong do quet SMTP": "Tấn công dò quét SMTP",
    "Tan cong do quet Telnet": "Tấn công dò quét Telnet",
    "Tan cong ung dung web": "Tấn công ứng dụng web",
    "Táº¥n cÃ´ng á»©ng dá»¥ng web": "Tấn công ứng dụng web",
}

RISK_LABELS = {
    "Very High": "Rất cao",
    "High": "Cao",
    "Medium": "Trung bình",
    "Low": "Thấp",
    "Minimal": "Rất thấp",
}

RISK_ALIASES = {
    "Rat cao": "Rất cao",
    "Ráº¥t cao": "Rất cao",
    "Trung binh": "Trung bình",
    "Trung bÃ¬nh": "Trung bình",
    "Thap": "Thấp",
    "Tháº¥p": "Thấp",
    "Rat thap": "Rất thấp",
    "Ráº¥t tháº¥p": "Rất thấp",
}

RISK_CLASSES = {
    "Rất cao": "risk-very-high",
    "Cao": "risk-high",
    "Trung bình": "risk-medium",
    "Thấp": "risk-low",
    "Rất thấp": "risk-minimal",
    "Rat cao": "risk-very-high",
    "Trung binh": "risk-medium",
    "Thap": "risk-low",
    "Rat thap": "risk-minimal",
    "Very High": "risk-very-high",
    "High": "risk-high",
    "Medium": "risk-medium",
    "Low": "risk-low",
    "Minimal": "risk-minimal",
}


def _serialize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value


def translate_prediction_label(label: str) -> str:
    mapped_label = PREDICTION_LABELS.get(label, label)
    return PREDICTION_ALIASES.get(mapped_label, mapped_label)


def translate_risk_label(label: str) -> str:
    mapped_label = RISK_LABELS.get(label, label)
    return RISK_ALIASES.get(mapped_label, mapped_label)


def risk_label_from_probability(score: float) -> str:
    if score > 0.8:
        return "Very High"
    if score > 0.6:
        return "High"
    if score > 0.4:
        return "Medium"
    if score > 0.2:
        return "Low"
    return "Minimal"


def risk_rank(label: str) -> int:
    normalized = (label or "").strip().lower()
    mapping = {
        "rat cao": 4,
        "rất cao": 4,
        "very high": 4,
        "cao": 3,
        "high": 3,
        "trung binh": 2,
        "trung bình": 2,
        "medium": 2,
        "thap": 1,
        "thấp": 1,
        "low": 1,
        "rat thap": 0,
        "rất thấp": 0,
        "minimal": 0,
    }
    return mapping.get(normalized, 0)


def risk_css_class(label: str) -> str:
    return RISK_CLASSES.get(translate_risk_label(label), "risk-minimal")


def build_risk_summary_html(label: str) -> str:
    translated_label = translate_risk_label(label)
    css_class = risk_css_class(translated_label)
    return (
        f'<div class="risk-summary {css_class}">'
        f'<span class="risk-label">Mức rủi ro</span>'
        f'<span class="risk-pill {css_class}">{translated_label}</span>'
        f"</div>"
    )


def is_priority_alert(prediction_label: str, risk_label: str) -> bool:
    normalized_prediction = translate_prediction_label(prediction_label)
    benign_prediction = translate_prediction_label("Benign")
    ddos_prediction = translate_prediction_label("DDoS")
    dos_prediction = translate_prediction_label("DoS")
    if normalized_prediction in {ddos_prediction, dos_prediction}:
        return risk_rank(risk_label) >= risk_rank("High")
    if normalized_prediction != benign_prediction:
        return True
    return risk_rank(risk_label) > 2


def clamp_attack_risk(prediction_label: str, risk_label: str) -> str:
    normalized_prediction = translate_prediction_label(prediction_label)
    normalized_risk = translate_risk_label(risk_label)
    ddos_prediction = translate_prediction_label("DDoS")
    dos_prediction = translate_prediction_label("DoS")

    if normalized_prediction == ddos_prediction:
        if risk_rank(normalized_risk) > risk_rank("High"):
            return translate_risk_label("High")
        if risk_rank(normalized_risk) < risk_rank("Medium"):
            return translate_risk_label("Medium")
        return normalized_risk

    if normalized_prediction == dos_prediction:
        if risk_rank(normalized_risk) > risk_rank("High"):
            return translate_risk_label("High")
        if risk_rank(normalized_risk) < risk_rank("Low"):
            return translate_risk_label("Low")
        return normalized_risk

    return normalized_risk


def prediction_filter_values(label: str) -> List[str]:
    normalized = translate_prediction_label(label)
    values = {label, normalized}
    for alias, canonical in PREDICTION_ALIASES.items():
        if canonical == normalized:
            values.add(alias)
    return [value for value in values if value]


def demo_prediction_filter_labels() -> List[str]:
    return [translate_prediction_label(label) for label in DEMO_FILTER_PREDICTION_KEYS]


def risk_filter_values(label: str) -> List[str]:
    normalized = translate_risk_label(label)
    values = {label, normalized}
    for alias, canonical in RISK_ALIASES.items():
        if canonical == normalized:
            values.add(alias)
    return [value for value in values if value]


def build_alert_record(features: Iterable[Any], classification: str, probability: float, risk: str) -> Dict[str, Any]:
    feature_values = list(features)
    record: Dict[str, Any] = {}
    ordered_fields = MODEL_FEATURE_FIELDS + FLOW_METADATA_FIELDS
    for index, field in enumerate(ordered_fields):
        record[field] = _serialize_value(feature_values[index])
    record["Classification"] = classification
    record["Probability"] = float(probability)
    record["Risk"] = risk
    return record


def feature_vector_from_record(record: Dict[str, Any]) -> List[float]:
    return [float(record[field]) for field in MODEL_FEATURE_FIELDS]


def ordered_record(record: Dict[str, Any]) -> Dict[str, Any]:
    return {field: record.get(field) for field in ALERT_FIELDS if field in record}
