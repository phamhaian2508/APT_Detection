from __future__ import annotations

import copy
import ipaddress
import json
import logging
import pickle
import traceback
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Any, Dict, List
from urllib.request import urlopen

import dill
import joblib
import numpy as np
import pandas as pd
import plotly
import plotly.graph_objs
from tensorflow import keras

from backend.features import (
    AE_FEATURES,
    DISPLAY_LABELS,
    build_risk_summary_html,
    build_alert_record,
    clamp_attack_risk,
    feature_vector_from_record,
    is_priority_alert,
    risk_label_from_probability,
    risk_rank,
    translate_prediction_label,
    translate_risk_label,
)
from backend.flood_heuristics import FloodAttackHeuristic
from backend.ftp_heuristics import FTPBruteForceHeuristic
from backend.service_bruteforce_heuristics import (
    build_rdp_bruteforce_heuristic,
    build_smb_bruteforce_heuristic,
    build_smtp_bruteforce_heuristic,
    build_telnet_bruteforce_heuristic,
)
from backend.ssh_heuristics import SSHBruteForceHeuristic


class GeoResolver:
    def __init__(self, enabled: bool = True, logger: logging.Logger | None = None) -> None:
        self._lock = Lock()
        self._country_cache: Dict[str, str] = {}
        self._pending_addresses: set[str] = set()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="geo-resolver")
        self.enabled = enabled
        self.logger = logger or logging.getLogger("apt_detection.inference.geo")

    @lru_cache(maxsize=1024)
    def _fetch_country_code(self, address: str) -> str | None:
        try:
            url = f"https://ipinfo.io/{address}/json" if address else "https://ipinfo.io/json"
            response = urlopen(url, timeout=1.2)
            payload = json.load(response)
            return payload.get("country")
        except Exception:
            self.logger.debug("Geolocation lookup failed for %s.", address, exc_info=True)
            return None

    def decorate_ip(self, address: str) -> str:
        try:
            if ipaddress.ip_address(address).is_private:
                return f'{address} <img src="/static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
        except ValueError:
            return address

        if not self.enabled:
            return address

        country = self._cached_country_code(address)
        if country is None:
            self._schedule_lookup(address)
            return address

        if country and len(country) == 2 and country.isalpha():
            flag = "".join(chr(127397 + ord(char.upper())) for char in country)
            return f'{address} <span class="country-flag" title="{country}">{flag}</span>'
        return f'{address} <span class="country-flag country-flag-unknown" title="UNKNOWN">&#127760;</span>'

    def _cached_country_code(self, address: str) -> str | None:
        with self._lock:
            return self._country_cache.get(address)

    def _schedule_lookup(self, address: str) -> None:
        with self._lock:
            if address in self._pending_addresses:
                return
            self._pending_addresses.add(address)
        self._executor.submit(self._resolve_and_store, address)

    def _resolve_and_store(self, address: str) -> None:
        country = self._fetch_country_code(address)
        with self._lock:
            self._country_cache[address] = country or ""
            self._pending_addresses.discard(address)


class InferenceService:
    def __init__(
        self,
        enable_geolocation: bool = True,
        enable_explanations: bool = True,
        enable_service_bruteforce_heuristics: bool = False,
        logger: logging.Logger | None = None,
    ) -> None:
        self._predict_lock = Lock()
        self.logger = logger or logging.getLogger("apt_detection.inference")
        self.geo_resolver = GeoResolver(enabled=enable_geolocation, logger=self.logger.getChild("geo"))
        self.ftp_heuristic = FTPBruteForceHeuristic()
        self.flood_heuristic = FloodAttackHeuristic()
        self.ssh_heuristic = SSHBruteForceHeuristic()
        self.service_bruteforce_heuristics = []
        if enable_service_bruteforce_heuristics:
            self.service_bruteforce_heuristics = [
                build_rdp_bruteforce_heuristic(),
                build_smb_bruteforce_heuristic(),
                build_telnet_bruteforce_heuristic(),
                build_smtp_bruteforce_heuristic(),
            ]
        self.ae_scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
        self.ae_model = keras.models.load_model("models/autoencoder_39ft.hdf5")
        with open("models/model.pkl", "rb") as model_file:
            self.classifier = pickle.load(model_file)
        self.explainer = None
        if enable_explanations:
            try:
                with open("models/explainer", "rb") as explain_file:
                    self.explainer = dill.load(explain_file)
            except Exception:
                traceback.print_exc()
                self.logger.warning("Could not load models/explainer; detail view will omit LIME explanation.")
        else:
            self.logger.info("LIME explanations are disabled by configuration.")

    def classify(self, features: List[Any], preview: bool = False) -> Dict[str, Any] | None:
        try:
            feature_vector = [np.nan if value in [np.inf, -np.inf] else float(value) for value in features[:39]]
        except (TypeError, ValueError):
            return None
        if np.isnan(feature_vector).any():
            return None

        with self._predict_lock:
            prediction = str(self.classifier.predict([feature_vector])[0])
            probabilities = self.classifier.predict_proba([feature_vector]).astype(float)[0]

        probability_score = float(np.max(probabilities))
        risk_probability = float(np.sum(probabilities[1:])) if len(probabilities) > 1 else 0.0
        risk_label = translate_risk_label(risk_label_from_probability(risk_probability))
        classification = translate_prediction_label(prediction)
        model_prediction = classification
        record = build_alert_record(features, classification, probability_score, risk_label)

        heuristic_match = self._evaluate_heuristic(self.ssh_heuristic, record, classification, preview=preview)
        if heuristic_match is not None:
            record["Classification"] = heuristic_match.classification
            record["Probability"] = max(float(record["Probability"]), heuristic_match.probability)
            record["Risk"] = heuristic_match.risk

        heuristic_match = self._evaluate_heuristic(
            self.ftp_heuristic,
            record,
            str(record["Classification"]),
            preview=preview,
        )
        if heuristic_match is not None:
            record["Classification"] = heuristic_match.classification
            record["Probability"] = max(float(record["Probability"]), heuristic_match.probability)
            record["Risk"] = heuristic_match.risk

        for heuristic in self.service_bruteforce_heuristics:
            heuristic_match = self._evaluate_heuristic(
                heuristic,
                record,
                str(record["Classification"]),
                preview=preview,
            )
            if heuristic_match is None:
                continue

            record["Classification"] = heuristic_match.classification
            record["Probability"] = max(float(record["Probability"]), heuristic_match.probability)
            record["Risk"] = heuristic_match.risk
            self._append_service_hint(record, heuristic_match.classification)

        flood_heuristic_match = self._evaluate_heuristic(
            self.flood_heuristic,
            record,
            str(record["Classification"]),
            preview=preview,
        )
        if flood_heuristic_match is not None:
            record["Classification"] = flood_heuristic_match.classification
            record["Probability"] = max(float(record["Probability"]), flood_heuristic_match.probability)
            record["Risk"] = flood_heuristic_match.risk

        self._suppress_unconfirmed_flood_prediction(
            record,
            model_prediction=model_prediction,
            flood_heuristic_match=flood_heuristic_match,
        )

        record["Risk"] = clamp_attack_risk(str(record["Classification"]), str(record["Risk"]))

        return record

    def classify_preview(self, features: List[Any]) -> Dict[str, Any] | None:
        return self.classify(features, preview=True)

    @staticmethod
    def _evaluate_heuristic(heuristic: Any, record: Dict[str, Any], current_prediction: str, preview: bool = False) -> Any:
        engine = copy.deepcopy(heuristic) if preview else heuristic
        return engine.evaluate(record, current_prediction)

    @staticmethod
    def _suppress_unconfirmed_flood_prediction(
        record: Dict[str, Any],
        model_prediction: str,
        flood_heuristic_match: Any,
    ) -> None:
        benign_prediction = translate_prediction_label("Benign")
        dos_prediction = translate_prediction_label("DoS")
        ddos_prediction = translate_prediction_label("DDoS")
        flood_predictions = {dos_prediction, ddos_prediction}
        normalized_model_prediction = translate_prediction_label(model_prediction)
        normalized_record_prediction = translate_prediction_label(str(record.get("Classification") or benign_prediction))

        if flood_heuristic_match is not None:
            return
        if normalized_model_prediction not in flood_predictions:
            return
        if normalized_record_prediction not in flood_predictions:
            return

        record["Classification"] = benign_prediction
        record["Risk"] = translate_risk_label("Low")
        record["Probability"] = min(float(record.get("Probability") or 0.0), 0.49)

    @staticmethod
    def _append_service_hint(record: Dict[str, Any], hint_label: str) -> None:
        normalized_hint = translate_prediction_label(hint_label)
        service_hints = record.setdefault("ServiceHints", [])
        if normalized_hint not in service_hints:
            service_hints.append(normalized_hint)

    def build_stream_payload(self, record: Dict[str, Any]) -> Dict[str, Any]:
        prediction = translate_prediction_label(record["Classification"])
        risk = translate_risk_label(record["Risk"])
        service_hints = [translate_prediction_label(hint) for hint in list(record.get("ServiceHints") or []) if hint]
        flow_key = "{src}-{dst}-{src_port}-{dst_port}-{protocol}".format(
            src=record["Src"],
            dst=record["Dest"],
            src_port=record["SrcPort"],
            dst_port=record["DestPort"],
            protocol=record["Protocol"],
        )
        return {
            "id": record["FlowID"],
            "flowKey": flow_key,
            "src": record["Src"],
            "srcDisplay": self.geo_resolver.decorate_ip(record["Src"]),
            "srcPort": record["SrcPort"],
            "dst": record["Dest"],
            "dstDisplay": self.geo_resolver.decorate_ip(record["Dest"]),
            "dstPort": record["DestPort"],
            "protocol": record["Protocol"],
            "start": record["FlowStartTime"],
            "lastSeen": record["FlowLastSeen"],
            "appName": record["PName"],
            "pid": record["PID"],
            "prediction": prediction,
            "serviceHints": service_hints,
            "probability": record["Probability"],
            "risk": risk,
            "isPriority": is_priority_alert(prediction, risk) or bool(service_hints),
            "isProvisional": False,
        }

    def build_detail_context(self, record: Dict[str, Any]) -> Dict[str, Any]:
        feature_vector = feature_vector_from_record(record)
        risk_html = build_risk_summary_html(str(record.get("Risk") or "Minimal"))

        exp_html = None
        if self.explainer is not None:
            detail_vector = np.asarray(feature_vector, dtype=float)
            with self._predict_lock:
                exp_html = self.explainer.explain_instance(
                    detail_vector,
                    lambda values: self.classifier.predict_proba(np.asarray(values, dtype=float)).astype(float),
                    num_features=6,
                    top_labels=1,
                ).as_html()

        X_transformed = self.ae_scaler.transform([feature_vector])
        with self._predict_lock:
            reconstructed = self.ae_model.predict(X_transformed, verbose=0)
        errors = reconstructed - X_transformed
        abs_errors = np.abs(errors[0])
        largest_indexes = np.argpartition(abs_errors, -5)[-5:]
        plot_div = plotly.offline.plot(
            {
                "data": [
                    plotly.graph_objs.Bar(
                        x=[AE_FEATURES[index] for index in largest_indexes],
                        y=errors[0][largest_indexes].tolist(),
                    )
                ]
            },
            include_plotlyjs=False,
            output_type="div",
        )

        display_record = dict(record)
        display_record["Classification"] = translate_prediction_label(display_record["Classification"])
        display_record["Risk"] = translate_risk_label(display_record["Risk"])
        display_record["ServiceHints"] = ", ".join(
            translate_prediction_label(hint) for hint in list(display_record.get("ServiceHints") or []) if hint
        ) or "-"

        flow_table = (
            pd.DataFrame.from_dict(display_record, orient="index", columns=["Value"])
            .rename(index=DISPLAY_LABELS)
            .to_html(classes="data")
        )

        return {
            "risk_html": risk_html,
            "explanation_html": exp_html,
            "ae_plot": plot_div,
            "flow_table": flow_table,
        }
