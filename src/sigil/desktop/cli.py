"""Command-line entry point: ``sigil [command]``.

Running without a command (double-click, autostart) is the same as ``serve``.

    serve [--no-tray] [--host H] [--port P]   run the agent (tray icon when available)
    diagnose [--json]                         check driver, tokens and certificates (no PIN)
    autostart enable|disable|status           start at login (per user, no admin rights)
    config init [--force]|path|show           create / locate / print the configuration
    version                                   print the version
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import struct
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sigil import SERVICE_NAME, __codename__, __version__, display_version
from sigil.container import build_container
from sigil.domain.errors import AgentError
from sigil.infrastructure import paths
from sigil.infrastructure.config import (
    AgentSettings,
    ConfigError,
    load_settings,
    resolve_config_path,
    write_config_template,
)
from sigil.infrastructure.logging_setup import configure_logging

from .autostart import autostart_backend, launch_command
from .server import AgentServer, PortState, probe_port
from .tray import TrayApp, tray_support

logger = logging.getLogger("sigil.cli")


def _out(text: str) -> None:
    """Print to stdout; windowed builds have none, so fall back to the log."""
    if sys.stdout is not None:
        print(text)
    else:
        logger.info(text)


def _err(text: str) -> None:
    if sys.stderr is not None:
        print(text, file=sys.stderr)
    else:
        logger.error(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigil",
        description="Local bridge between your web system and a PKCS#11 signing token.",
    )
    parser.add_argument("--config", type=Path, help="config file (default: per-OS location)")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the agent (default command)")
    serve.add_argument("--no-tray", action="store_true", help="run without a tray icon")
    serve.add_argument("--host", help="listen address (default 127.0.0.1)")
    serve.add_argument("--port", type=int, help="listen port (default 8765)")

    diagnose = sub.add_parser("diagnose", help="check driver, tokens and certificates")
    diagnose.add_argument("--json", action="store_true", help="machine-readable output")

    autostart = sub.add_parser("autostart", help="start the agent at login")
    autostart.add_argument("action", choices=["enable", "disable", "status"])

    config = sub.add_parser("config", help="manage the configuration file")
    config.add_argument("action", choices=["init", "path", "show"])
    config.add_argument("--force", action="store_true", help="overwrite with 'init'")

    sub.add_parser("version", help="print the version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and run the command; returns the process exit code."""
    args = build_parser().parse_args(argv)
    command = args.command or "serve"
    exit_code = _run_without_settings(command, args)
    return exit_code if exit_code is not None else _run_with_settings(command, args)


def _run_without_settings(command: str, args: argparse.Namespace) -> int | None:
    """Commands that must work even when the configuration is broken."""
    if command == "version":
        _out(f"{SERVICE_NAME} {display_version()}")
        return 0
    if command == "config" and args.action in ("init", "path"):
        return _config_file_command(args.action, args.config, force=args.force)
    if command == "autostart":
        return _autostart(args.action)
    return None


def _run_with_settings(command: str, args: argparse.Namespace) -> int:
    try:
        settings = load_settings(
            args.config, host=getattr(args, "host", None), port=getattr(args, "port", None)
        )
    except ConfigError as exc:
        _err(str(exc))
        return 2

    if command == "config":  # show
        _out(json.dumps(settings.model_dump(mode="json"), indent=2))
        return 0
    if command == "diagnose":
        return _diagnose(settings, args.config, as_json=args.json)
    return _serve(settings, use_tray=settings.tray and not getattr(args, "no_tray", False))


# --------------------------------------------------------------------------- commands


def _config_file_command(action: str, explicit: Path | None, *, force: bool) -> int:
    path = resolve_config_path(explicit)
    if action == "path":
        _out(str(path))
        return 0
    try:
        _out(f"Wrote {write_config_template(path, overwrite=force)}")
    except ConfigError as exc:
        _err(str(exc))
        return 1
    return 0


def _autostart(action: str) -> int:
    backend = autostart_backend()
    try:
        if action == "enable":
            _out(backend.enable(launch_command()))
        elif action == "disable":
            _out(backend.disable())
        else:
            _out("enabled" if backend.is_enabled() else "disabled")
    except OSError as exc:
        _err(f"Could not change start-at-login: {exc}")
        return 1
    return 0


def _serve(settings: AgentSettings, *, use_tray: bool) -> int:
    log_dir = configure_logging(settings.log_level, settings.log_dir or paths.log_dir())
    logger.info("Sigil %s starting on %s", display_version(), settings.base_url)
    if not settings.is_loopback_only:
        logger.warning(
            "Listening on %s — the agent is reachable from other machines. "
            "Only do this on a trusted network.",
            settings.host,
        )

    state = probe_port(settings)
    if state is PortState.THIS_AGENT:
        _out(f"Sigil is already running at {settings.base_url}.")
        return 0
    if state is PortState.OTHER_PROGRAM:
        _err(f"Port {settings.port} is used by another program; set another 'port' in the config.")
        return 1

    from sigil.api import create_app  # noqa: PLC0415 - keeps CLI start-up light

    container = build_container(settings)
    server = AgentServer(create_app(container), settings)
    if use_tray:
        available, reason = tray_support()
        if available:
            tray = TrayApp(server, container.token_service, settings, autostart_backend(), log_dir)
            return tray.run()
        logger.warning("Running without tray icon: %s", reason)
    server.run()
    return 0


def _diagnose(settings: AgentSettings, config_file: Path | None, *, as_json: bool) -> int:
    configure_logging("ERROR", None)
    container = build_container(settings)
    config_path = resolve_config_path(config_file)
    report: dict[str, Any] = {
        "agent": {
            "version": __version__,
            "codename": __codename__,
            "python": f"{platform.python_version()} ({struct.calcsize('P') * 8}-bit)",
            "executable": sys.executable,
            "frozen": bool(getattr(sys, "frozen", False)),
        },
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "config_file": {"path": str(config_path), "exists": config_path.is_file()},
        "log_dir": str(settings.log_dir or paths.log_dir()),
        "base_url": settings.base_url,
        "allowed_origins": list(settings.allowed_origins),
        "tsa_url": settings.tsa_url,
    }
    status = container.token_service.driver_status()
    report["driver"] = asdict(status)
    if status.loaded:
        report["tokens"] = _token_report(container)

    if as_json:
        _out(json.dumps(report, indent=2, default=str))
    else:
        _out(_render_report(report))
    return 0 if status.loaded else 3


def _token_report(container: Any) -> list[dict[str, Any]] | dict[str, str]:
    try:
        tokens = container.token_service.list_tokens()
    except AgentError as exc:
        return {"error": f"{exc.code}: {exc.message}"}
    result: list[dict[str, Any]] = []
    for token in tokens:
        entry: dict[str, Any] = asdict(token)
        try:
            entry["certificates"] = [
                {
                    "cert_id": c.id_hex,
                    "subject": c.subject_common_name or c.subject,
                    "issuer": c.issuer_common_name or c.issuer,
                    "not_after": c.not_after.isoformat(),
                    "key_usage": sorted(c.key_usage) if c.key_usage is not None else None,
                    "is_ca": c.is_ca,
                    "has_private_key": c.has_private_key,
                }
                for c in container.token_service.list_certificates(token.serial)
            ]
        except AgentError as exc:
            entry["certificates"] = f"{exc.code}: {exc.message}"
        result.append(entry)
    return result


def _render_report(report: dict[str, Any]) -> str:
    agent, os_info, driver = report["agent"], report["os"], report["driver"]
    lines = [
        f'Sigil {agent["version"]} "{agent["codename"]}"  —  Python {agent["python"]}',
        f"OS:            {os_info['system']} {os_info['release']} ({os_info['machine']})",
        f"Config file:   {report['config_file']['path']}"
        + ("" if report["config_file"]["exists"] else "  (not created; defaults in use)"),
        f"Logs:          {report['log_dir']}",
        f"Listens on:    {report['base_url']}",
        f"Origins:       {', '.join(report['allowed_origins']) or '(none)'}",
        f"TSA:           {report['tsa_url'] or '(not configured)'}",
        "",
    ]
    if driver["loaded"]:
        lines.append(
            f"Driver:        OK  {driver['module_path']}  "
            f"({driver['manufacturer']}, v{driver['library_version']})"
        )
    else:
        lines.append(f"Driver:        NOT AVAILABLE  [{driver['error_code']}] {driver['error']}")
        lines.append("Searched:")
        lines += [f"  - {p}" for p in driver["searched"]]
        return "\n".join(lines)

    tokens = report.get("tokens")
    if isinstance(tokens, dict):
        lines.append(f"Tokens:        ERROR {tokens['error']}")
    elif not tokens:
        lines.append("Tokens:        none connected")
    else:
        for token in tokens:
            pin = token["pin_status"]
            flags = [name for name in ("count_low", "final_try", "locked") if pin[name]]
            lines.append(
                f"Token:         {token['label']}  serial={token['serial']}  "
                f"({token['manufacturer']} {token['model']})"
                + (f"  PIN: {', '.join(flags)}" if flags else "")
            )
            certs = token["certificates"]
            if isinstance(certs, str):
                lines.append(f"  certificates: {certs}")
                continue
            for cert in certs:
                kind = "CA  " if cert["is_ca"] else "USER"
                key = {True: "key", False: "no key", None: "key?"}[cert["has_private_key"]]
                lines.append(
                    f"  [{kind}] id={cert['cert_id'] or '-'}  {cert['subject']}  "
                    f"(until {cert['not_after'][:10]}, {key})"
                )
    return "\n".join(lines)
