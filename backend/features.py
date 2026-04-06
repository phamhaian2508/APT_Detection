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
    "SSH-Patator": "Tấn công dò quét SSH",
    "Web Attack": "Tấn công ứng dụng web",
}

RISK_LABELS = {
    "Very High": "Rất cao",
    "High": "Cao",
    "Medium": "Trung bình",
    "Low": "Thấp",
    "Minimal": "Rất thấp",
}

RISK_CLASSES = {
    "Rất cao": "risk-very-high",
    "Cao": "risk-high",
    "Trung bình": "risk-medium",
    "Thấp": "risk-low",
    "Rất thấp": "risk-minimal",
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
    return PREDICTION_LABELS.get(label, label)


def translate_risk_label(label: str) -> str:
    return RISK_LABELS.get(label, label)


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
        "rất cao": 4,
        "very high": 4,
        "cao": 3,
        "high": 3,
        "trung bình": 2,
        "medium": 2,
        "thấp": 1,
        "low": 1,
        "rất thấp": 0,
        "minimal": 0,
    }
    return mapping.get(normalized, 0)


def risk_css_class(label: str) -> str:
    return RISK_CLASSES.get(label, "risk-minimal")


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
