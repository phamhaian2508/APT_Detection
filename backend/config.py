from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class AppConfig:
    secret_key: str
    debug: bool
    web_host: str
    web_port: int
    enable_service_bruteforce_heuristics: bool
    auto_start_capture: bool
    db_path: str
    output_csv_path: str
    input_csv_path: str
    flow_timeout: int
    sniff_timeout: float
    queue_size: int
    process_refresh_interval: float
    enable_geolocation: bool
    enable_explanations: bool
    reset_data_on_start: bool
    reset_data_on_page_load: bool
    write_compatibility_logs: bool
    log_level: str
    log_file: str
    socketio_logging: bool

    @classmethod
    def from_env(cls, project_root: Path) -> "AppConfig":
        log_dir = project_root / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        data_dir = project_root / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        return cls(
            secret_key=os.getenv("APT_SECRET_KEY", "secret!"),
            debug=_get_bool("APT_DEBUG", False),
            web_host=os.getenv("APT_WEB_HOST", "0.0.0.0"),
            web_port=_get_int("APT_WEB_PORT", 5000),
            enable_service_bruteforce_heuristics=_get_bool("APT_ENABLE_SERVICE_BRUTEFORCE_HEURISTICS", False),
            auto_start_capture=_get_bool("APT_AUTO_START_CAPTURE", False),
            db_path=os.getenv("APT_DB_PATH", str(data_dir / "alerts.db")),
            output_csv_path=os.getenv("APT_OUTPUT_CSV_PATH", str(project_root / "output_logs.csv")),
            input_csv_path=os.getenv("APT_INPUT_CSV_PATH", str(project_root / "input_logs.csv")),
            flow_timeout=_get_int("APT_FLOW_TIMEOUT", 5),
            sniff_timeout=_get_float("APT_SNIFF_TIMEOUT", 1.0),
            queue_size=_get_int("APT_QUEUE_SIZE", 5000),
            process_refresh_interval=_get_float("APT_PROCESS_REFRESH_INTERVAL", 2.0),
            enable_geolocation=_get_bool("APT_ENABLE_GEOLOCATION", True),
            enable_explanations=_get_bool("APT_ENABLE_EXPLANATIONS", True),
            reset_data_on_start=_get_bool("APT_RESET_DATA_ON_START", True),
            reset_data_on_page_load=_get_bool("APT_RESET_DATA_ON_PAGE_LOAD", False),
            write_compatibility_logs=_get_bool("APT_WRITE_COMPATIBILITY_LOGS", False),
            log_level=os.getenv("APT_LOG_LEVEL", "INFO").upper(),
            log_file=os.getenv("APT_LOG_FILE", str(log_dir / "app.log")),
            socketio_logging=_get_bool("APT_SOCKETIO_LOGGING", False),
        )
