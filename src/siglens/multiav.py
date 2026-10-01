from __future__ import annotations

from pathlib import Path
import json
import re
import shutil

from .external_tools import defender_scan, clamav_scan
from .utils import run_command


def _combined_output(result: dict) -> str:
    return "\n".join(
        str(result.get(key))
        for key in ("stdout", "stderr")
        if result.get(key)
    )


def _extract_regex(
    pattern: str | None,
    text: str,
) -> str | None:
    if not pattern:
        return None

    try:
        match = re.search(
            pattern,
            text,
            re.IGNORECASE | re.MULTILINE,
        )
    except re.error as exc:
        return f"<invalid regex: {exc}>"

    if not match:
        return None

    if "signature" in match.groupdict():
        return match.group("signature")

    if match.groups():
        return match.group(1)

    return match.group(0)


def normalize_result(
    name: str,
    raw: dict,
    *,
    engine_type: str,
    signature: str | None = None,
    status: str | None = None,
    offset: int | None = None,
) -> dict:
    available = bool(
        raw.get(
            "available",
            True,
        )
    )

    if not available:
        status = "unavailable"

    elif status is None:
        status = "unknown"

    return {
        "name": name,
        "type": engine_type,
        "available": available,
        "status": status,
        "signature": signature,
        "offset": offset,
        "offset_source": (
            "native_engine_output"
            if offset is not None
            else None
        ),
        "whole_file_only": True,
        "returncode": raw.get("returncode"),
        "stdout": raw.get("stdout", ""),
        "stderr": raw.get("stderr", ""),
        "error": raw.get("error"),
        "command": raw.get("args"),
        "engine_path": raw.get("engine_path"),
        "file_existed_before_scan": raw.get(
            "file_existed_before_scan"
        ),
        "file_exists_after_scan": raw.get(
            "file_exists_after_scan"
        ),
        "output_excerpt": (
            _combined_output(raw)[:4000]
        ),
    }


def _history_rows(raw: dict) -> list[dict]:
    value = (
        raw.get(
            "detections",
            {},
        )
        .get("json")
    )

    if isinstance(
        value,
        list,
    ):
        return value

    if isinstance(
        value,
        dict,
    ):
        return [value]

    return []


def scan_builtin(
    name: str,
    builtin: str,
    path: Path,
) -> dict:

    # ==============================================================
    # Microsoft Defender
    # ==============================================================

    if builtin == "defender":
        raw = defender_scan(
            path
        )

        if not raw.get(
            "available"
        ):
            return normalize_result(
                name,
                raw,
                engine_type="builtin:defender",
            )

        history = _history_rows(
            raw
        )

        signature = next(
            (
                str(
                    row.get(
                        "ThreatName"
                    )
                )
                for row in reversed(
                    history
                )
                if row.get(
                    "ThreatName"
                )
            ),
            None,
        )

        text = _combined_output(
            raw
        )

        lower = text.lower()

        returncode = raw.get(
            "returncode"
        )

        # ----------------------------------------------------------
        # Defender verdict
        # ----------------------------------------------------------
        #
        # The explicit MpCmdRun result is interpreted primarily from
        # its exit code, matching ThreatCheck-style behaviour:
        #
        #   0 -> CLEAN
        #   2 -> DETECTED
        #
        # Defender real-time protection can react asynchronously to
        # the temporary file, so a path-matched Defender history row
        # is also accepted as DETECTED evidence.
        #
        # UNKNOWN / ERROR are never silently converted to CLEAN.
        # ----------------------------------------------------------

        detection_source = None

        if returncode == 2:
            status = "detected"
            detection_source = (
                "mpcmdrun_exit_code"
            )

        elif history:
            status = "detected"
            detection_source = (
                "defender_history"
            )

        elif any(
            marker in lower
            for marker in (
                "threats found",
                "found threat",
                "malware detected",
                "infected",
            )
        ):
            status = "detected"
            detection_source = (
                "mpcmdrun_output"
            )

        elif returncode == 0:
            status = "clean"
            detection_source = (
                "mpcmdrun_exit_code"
            )

        elif raw.get(
            "error"
        ):
            status = "error"

        else:
            status = "unknown"

        # ----------------------------------------------------------
        # Signature extraction
        # ----------------------------------------------------------

        if not signature:
            for pattern in (
                (
                    r"(?P<signature>"
                    r"(?:Trojan|HackTool|Backdoor|Virus|Worm|PUA|"
                    r"Behavior|Exploit|Ransom|VirTool|Tool|Suspicious)"
                    r":[^\r\n]+)"
                ),
                (
                    r"Threat(?:\s+Name)?\s*[:=]\s*"
                    r"(?P<signature>[^\r\n]+)"
                ),
            ):
                signature = _extract_regex(
                    pattern,
                    text,
                )

                if signature:
                    break

        result = normalize_result(
            name,
            raw,
            engine_type="builtin:defender",
            signature=signature,
            status=status,
        )

        result[
            "detection_history"
        ] = history

        result[
            "detection_source"
        ] = detection_source

        return result

    # ==============================================================
    # ClamAV
    # ==============================================================

    if builtin == "clamav":
        raw = clamav_scan(
            path
        )

        if not raw.get(
            "available"
        ):
            return normalize_result(
                name,
                raw,
                engine_type="builtin:clamav",
            )

        text = _combined_output(
            raw
        )

        signature = _extract_regex(
            r":\s*(?P<signature>.+?)\s+FOUND(?:\r?$)",
            text,
        )

        rc = raw.get(
            "returncode"
        )

        if (
            signature
            or rc == 1
        ):
            status = "detected"

        elif rc == 0:
            status = "clean"

        elif rc == 2:
            status = "error"

        else:
            status = "unknown"

        return normalize_result(
            name,
            raw,
            engine_type="builtin:clamav",
            signature=signature,
            status=status,
        )

    return {
        "name": name,
        "type": (
            f"builtin:{builtin}"
        ),
        "available": False,
        "status": "unavailable",
        "error": (
            f"Unknown builtin engine: "
            f"{builtin}"
        ),
    }


def scan_cli(
    engine: dict,
    path: Path,
) -> dict:

    name = (
        engine.get("name")
        or "Unnamed CLI engine"
    )

    argv = engine.get(
        "argv"
    )

    if (
        not isinstance(
            argv,
            list,
        )
        or not argv
    ):
        return {
            "name": name,
            "type": "cli",
            "available": False,
            "status": "unavailable",
            "error": (
                "Engine requires a "
                "non-empty argv list"
            ),
        }

    resolved = []

    for index, item in enumerate(
        argv
    ):
        item = str(
            item
        ).replace(
            "{file}",
            str(path),
        )

        if index == 0:
            found = shutil.which(
                item
            )

            if found:
                item = found

            elif not Path(
                item
            ).exists():
                return {
                    "name": name,
                    "type": "cli",
                    "available": False,
                    "status": "unavailable",
                    "error": (
                        "Scanner executable "
                        f"not found: {item}"
                    ),
                }

        resolved.append(
            item
        )

    raw = run_command(
        resolved,
        timeout=int(
            engine.get(
                "timeout",
                300,
            )
        ),
    )

    raw["available"] = (
        not bool(
            raw.get(
                "error"
            )
        )
    )

    text = _combined_output(
        raw
    )

    rc = raw.get(
        "returncode"
    )

    detected = (
        bool(
            re.search(
                engine[
                    "detect_regex"
                ],
                text,
                re.I | re.M,
            )
        )
        if engine.get(
            "detect_regex"
        )
        else False
    )

    clean = (
        bool(
            re.search(
                engine[
                    "clean_regex"
                ],
                text,
                re.I | re.M,
            )
        )
        if engine.get(
            "clean_regex"
        )
        else False
    )

    detected_codes = {
        int(value)
        for value in engine.get(
            "detected_exit_codes",
            [],
        )
    }

    clean_codes = {
        int(value)
        for value in engine.get(
            "clean_exit_codes",
            [],
        )
    }

    if (
        detected
        or rc in detected_codes
    ):
        status = "detected"

    elif (
        clean
        or rc in clean_codes
    ):
        status = "clean"

    elif (
        engine.get(
            "assume_zero_exit_clean"
        )
        and rc == 0
    ):
        status = "clean"

    elif raw.get(
        "error"
    ):
        status = "error"

    else:
        status = "unknown"

    signature = _extract_regex(
        engine.get(
            "signature_regex"
        ),
        text,
    )

    offset = None

    offset_raw = _extract_regex(
        engine.get(
            "offset_regex"
        ),
        text,
    )

    if (
        offset_raw
        and not offset_raw.startswith(
            "<invalid regex"
        )
    ):
        try:
            offset = int(
                offset_raw,
                0,
            )
        except Exception:
            pass

    result = normalize_result(
        name,
        raw,
        engine_type="cli",
        signature=signature,
        status=status,
        offset=offset,
    )

    result[
        "config"
    ] = {
        key: engine.get(
            key
        )
        for key in (
            "detect_regex",
            "clean_regex",
            "signature_regex",
            "offset_regex",
        )
    }

    return result


def load_config(
    path: Path,
) -> dict:
    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if (
        not isinstance(
            data,
            dict,
        )
        or not isinstance(
            data.get(
                "engines"
            ),
            list,
        )
    ):
        raise ValueError(
            "Config must contain "
            "an 'engines' array"
        )

    return data


def scan_engines(
    path: Path,
    config_path: Path,
) -> dict:

    config = load_config(
        config_path
    )

    results = []

    for engine in config.get(
        "engines",
        [],
    ):
        if not engine.get(
            "enabled",
            True,
        ):
            continue

        name = (
            engine.get(
                "name"
            )
            or engine.get(
                "builtin"
            )
            or "Unnamed engine"
        )

        kind = engine.get(
            "type",
            "cli",
        )

        if kind == "builtin":
            results.append(
                scan_builtin(
                    name,
                    str(
                        engine.get(
                            "builtin",
                            "",
                        )
                    ).lower(),
                    path,
                )
            )

        elif kind == "cli":
            results.append(
                scan_cli(
                    engine,
                    path,
                )
            )

        else:
            results.append(
                {
                    "name": name,
                    "type": kind,
                    "available": False,
                    "status": "unavailable",
                    "error": (
                        "Unsupported "
                        f"engine type: {kind}"
                    ),
                }
            )

    states = (
        "detected",
        "clean",
        "unknown",
        "error",
        "unavailable",
    )

    summary = {
        state: sum(
            1
            for row in results
            if row.get(
                "status"
            ) == state
        )
        for state in states
    }

    summary[
        "total"
    ] = len(
        results
    )

    return {
        "config": str(
            config_path
        ),
        "mode": (
            "whole_file_multi_engine"
        ),
        "results": results,
        "summary": summary,
    }
