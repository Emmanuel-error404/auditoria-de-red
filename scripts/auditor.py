#!/usr/bin/env python3
"""Auditor GNS3 de un solo archivo: Audit Only o flujo PRE/Apply/POST."""

import argparse
import csv
import getpass
import html
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

from netmiko import ConnectHandler

# Completa las IP de administración del laboratorio. No agregues contraseñas.
DEVICES = [
    {"id": "R1", "name": "Cisco 7200", "adapter": "cisco_ios_15_2", "device_type": "cisco_ios", "host": "10.20.79.1", "port": 22},
    {"id": "SW1", "name": "Cisco vIOS L2", "adapter": "cisco_vios_l2_15_2", "device_type": "cisco_ios", "host": "10.20.98.2", "port": 22},
    {"id": "FW1", "name": "FortiGate 7.0.9", "adapter": "fortigate_7_0_9", "device_type": "fortinet", "host": "10.20.98.1", "port": 22, "management_interface": "port3"},
]

COMMANDS = {
    "cisco_ios_15_2": ["show version", "show running-config", "show ip ssh", "show ip http server status"],
    "cisco_vios_l2_15_2": ["show version", "show running-config", "show ip ssh", "show ip http server status"],
    "fortigate_7_0_9": [
        "get system status", "get system dns", "get system global", "diagnose sys ntp status",
        "show full-configuration system ntp", "show full-configuration system interface", "show firewall policy",
    ],
}
VTY_COMMAND = "show running-config | section line vty"

# Solo estos controles tienen aquí una acción acotada y un comando de reversión.
# Las claves del secreto se solicitan al ejecutar Apply y nunca van a los informes.
APPLY_CONTROL_IDS = {
    "1.1.2.4", "1.1.4.1", "1.1.3.3",  # Cisco IOS: timeout, enable secret, MOTD
    "2.1.1", "2.1.5", "2.2.2", "2.4.4",  # FortiOS: banner, hostname, lockout, timeout
}

CISCO_BENCHMARK = {
    "title": "CIS Cisco IOS Benchmark v2.2 (archived/legacy), Level 1 selected controls",
    "source": "https://www.cisecurity.org/-/jssmedia/Project/cisecurity/cisecurity/data/media/files/uploads/2017/04/CIS_Cisco_IOS_Benchmark_v22.pdf",
    "version_reference": "https://www.cisecurity.org/unsupported-cis-benchmarks",
    "scope_note": "Guía genérica archivada de Cisco IOS, no específica de IOS 15.2 ni de vIOS L2. Se usa como referencia cercana; solo se evalúan los controles automatizados listados y no equivale a una certificación exacta.",
}
FORTI_BENCHMARK = {
    "title": "CIS Fortigate 7.0.x Benchmark v1.2.0, Level 1 selected controls",
    "source": "https://www.cisecurity.org/benchmark/fortinet",
    "version_reference": "https://community.fortinet.com/fortigate-3/technical-tip-cis-benchmark-compliance-for-fortigate-200849",
    "scope_note": "La versión v1.2.0 es la más cercana para FortiOS 7.0.9; fue probada con 7.0.10. Los resultados son una evaluación orientativa del parche 7.0.9, no una validación exacta del benchmark. port1 se conserva y el control manual de servicios en WAN no se altera.",
}


def redact(text):
    marker = re.compile(r"(?i)\b(password|passwd|secret|token|api[-_ ]?key|private[-_ ]?key|psk)\b")
    return "\n".join("<REDACTED SENSITIVE LINE>" if marker.search(line) else line for line in text.splitlines())


def assess_vty_timeout(text):
    blocks, current = [], None
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"^line\s+vty\s+(\d+)(?:\s+(\d+))?\s*$", line, re.I)
        if match:
            if current:
                blocks.append(current)
            current = {"selector": f"line vty {match.group(1)}" + (f" {match.group(2)}" if match.group(2) else ""), "timeout": None}
        elif current:
            timeout = re.match(r"^exec-timeout\s+(\d+)\s+(\d+)", line, re.I)
            if timeout:
                current["timeout"] = (int(timeout.group(1)), int(timeout.group(2)))
    if current:
        blocks.append(current)
    if not blocks:
        return "ERROR", "No se encontraron líneas VTY para evaluar.", []
    failures = []
    for block in blocks:
        minutes, seconds = block["timeout"] if block["timeout"] is not None else (10, 0)
        block["effective_timeout_seconds"] = minutes * 60 + seconds
        if (minutes == 0 and seconds == 0) or minutes * 60 + seconds > 600:
            failures.append(block["selector"])
    if failures:
        return "FAIL", "Timeout ilimitado o mayor a 10 minutos: " + ", ".join(failures), blocks
    return "PASS", "Todas las líneas VTY tienen timeout de hasta 10 minutos.", blocks


def control_result(control_id, title, status, summary, evidence, benchmark):
    return {
        "control_id": control_id, "benchmark": benchmark["title"], "title": title,
        "status": status, "summary": summary, "evidence": evidence,
        "source": benchmark["source"],
    }


def command_failed(text):
    return not text.strip() or bool(re.search(
        r"(?im)(%\s*(?:invalid|incomplete|ambiguous|unknown)|invalid input|command fail|permission denied|not authorized|parse error|unknown action)",
        text,
    ))


def cisco_vty_blocks(config):
    blocks, current = [], None
    for raw in config.splitlines():
        line = raw.strip()
        match = re.match(r"^line\s+vty\s+(\d+)(?:\s+(\d+))?\s*$", line, re.I)
        if match:
            if current:
                blocks.append(current)
            current = {"selector": line.lower(), "lines": []}
        elif current:
            current["lines"].append(line.lower())
    if current:
        blocks.append(current)
    return blocks


def assess_cisco_controls(config, ssh_output, http_output):
    if command_failed(config):
        return [control_result(
            "CISCO-CONFIG", "Cisco IOS controls (configuración no disponible)", "NOT_EVALUATED",
            "show running-config no devolvió una configuración evaluable; revisa privilegios y evidencia.",
            config.strip()[:240] or "Sin salida de configuración.", CISCO_BENCHMARK,
        )]
    controls = []
    username_lines = re.findall(r"(?im)^\s*username\s+.+$", config)
    encrypted_users = bool(username_lines) and all(
        re.search(r"\bsecret\s+(?:5|8|9)\s+\S+", line, re.I) and not re.search(r"\bpassword\s+", line, re.I)
        for line in username_lines
    )
    controls.append(control_result(
        "1.1.2.1", "Require Local User and Encrypted Password",
        "PASS" if encrypted_users else ("FAIL" if username_lines else "FAIL"),
        "Se encontraron usuarios locales con secret cifrado." if encrypted_users else
        ("Hay usuarios sin secret cifrado tipo 5, 8 o 9." if username_lines else "No se encontró una cuenta local en la configuración."),
        f"Usuarios locales encontrados: {len(username_lines)}; no se incluyen hashes en el informe.", CISCO_BENCHMARK,
    ))

    ssh_enabled = bool(re.search(r"ssh enabled\s*-\s*version\s+2(?:\.0)?", ssh_output, re.I))
    vty_blocks = cisco_vty_blocks(config)
    vty_ssh_only = bool(vty_blocks) and all(
        any(re.match(r"transport input\s+ssh$", line) for line in block["lines"])
        for block in vty_blocks
    )
    controls.append(control_result(
        "1.1.2.2", "Require SSH for Remote Device Access",
        "PASS" if ssh_enabled and vty_ssh_only else ("FAIL" if not command_failed(ssh_output) and vty_blocks else "NOT_EVALUATED"),
        "SSH v2 está activo y las líneas VTY aceptan solo SSH." if ssh_enabled and vty_ssh_only else
        "No se confirmó SSH v2 junto con acceso VTY limitado a SSH.",
        f"show ip ssh: {ssh_output.strip()[:240]}; líneas VTY encontradas: {len(vty_blocks)}.", CISCO_BENCHMARK,
    ))
    transport_ok = bool(vty_blocks) and all(
        any(line.startswith("transport input ") and "ssh" in line.split()[2:] and "telnet" not in line.split()[2:] and "all" not in line.split()[2:]
            for line in block["lines"])
        for block in vty_blocks
    )
    controls.append(control_result(
        "1.1.2.3", "Require VTY Transport SSH",
        "PASS" if transport_ok else ("FAIL" if vty_blocks else "NOT_EVALUATED"),
        "Todas las líneas VTY declaran SSH y excluyen Telnet." if transport_ok else "Una o más líneas VTY no limitan el transporte a SSH.",
        "\n".join(line for block in vty_blocks for line in block["lines"] if line.startswith("transport input")) or "No se encontró transport input en VTY.", CISCO_BENCHMARK,
    ))

    timeout_status, timeout_summary, timeout_details = assess_vty_timeout(config)
    controls.append(control_result(
        "1.1.2.4", "Require Timeout for Login Sessions", timeout_status,
        timeout_summary, json.dumps(timeout_details, ensure_ascii=False), CISCO_BENCHMARK,
    ))

    enable_secret = bool(re.search(r"(?im)^\s*enable\s+secret\s+(?:5|8|9)\s+\S+", config))
    controls.append(control_result(
        "1.1.4.1", "Require Enable Secret", "PASS" if enable_secret else "FAIL",
        "Se encontró enable secret cifrado." if enable_secret else "No se encontró enable secret cifrado tipo 5, 8 o 9.",
        "La evidencia indica presencia/ausencia; el hash no se registra.", CISCO_BENCHMARK,
    ))

    has_motd = bool(re.search(r"(?im)^\s*banner\s+motd\s+\S", config))
    controls.append(control_result(
        "1.1.3.3", "Require MOTD Banner", "PASS" if has_motd else "FAIL",
        "Se encontró un banner MOTD." if has_motd else "No se encontró banner MOTD en la configuración.",
        "Presencia de la línea banner motd; el texto no se copia al resumen.", CISCO_BENCHMARK,
    ))

    http_lower = http_output.lower()
    active_http = bool(re.search(r"http server status:\s*enabled", http_lower)) or bool(re.search(r"(?im)^\s*ip http server\s*$", config))
    http_known = ("http server status" in http_lower and not command_failed(http_output)) or bool(re.search(r"(?im)^\s*no ip http server\s*$", config)) or active_http
    controls.append(control_result(
        "1.2.2.5", "Forbid IP HTTP Server",
        "FAIL" if active_http else ("PASS" if http_known else "NOT_EVALUATED"),
        "El servidor HTTP está habilitado." if active_http else ("El servidor HTTP aparece deshabilitado." if http_known else "No se pudo determinar el estado efectivo del servidor HTTP."),
        http_output.strip()[:240] or "Sin salida útil del comando de estado HTTP.", CISCO_BENCHMARK,
    ))

    for control_id, title, regex, positive in [
        ("1.2.3.6", "Require Service Timestamps for Debug Messages", r"^service timestamps debug datetime", "Se configuran marcas de tiempo para debug."),
        ("1.2.3.7", "Require Service Timestamps in Log Messages", r"^service timestamps log datetime", "Se configuran marcas de tiempo para logs."),
    ]:
        found = bool(re.search(r"(?im)\s*" + regex, config))
        controls.append(control_result(
            control_id, title, "PASS" if found else "FAIL",
            positive if found else "No se encontró la configuración requerida de timestamps.",
            next((line.strip() for line in config.splitlines() if re.search(regex, line.strip(), re.I)), "Línea de timestamp ausente."), CISCO_BENCHMARK,
        ))
    return controls


def forti_value(text, name):
    match = re.search(r"(?im)^\s*(?:set\s+)?" + re.escape(name) + r"\s*(?::|\s)\s*['\"]?([^\s'\"]+)", text)
    return match.group(1).strip("'\"") if match else None


def assess_forti_controls(outputs):
    controls = []
    status = outputs.get("get system status", "")
    dns = outputs.get("get system dns", "")
    global_cfg = outputs.get("get system global", "")
    ntp = outputs.get("diagnose sys ntp status", "")
    interfaces = outputs.get("show full-configuration system interface", "")
    policies = outputs.get("show firewall policy", "")

    primary_dns = forti_value(dns, "primary")
    dns_ok = bool(primary_dns and primary_dns not in {"0.0.0.0", "0.0.0.0/0"})
    controls.append(control_result("1.1", "Ensure DNS server is configured", "PASS" if dns_ok else ("FAIL" if not command_failed(dns) else "NOT_EVALUATED"),
        f"DNS primario observado: {primary_dns}." if dns_ok else "No se pudo confirmar una dirección DNS primaria configurada.",
        f"primary={primary_dns or 'no observado'}", FORTI_BENCHMARK))

    banner = forti_value(global_cfg, "pre-login-banner")
    controls.append(control_result("2.1.1", "Ensure Pre-Login Banner is set", "PASS" if banner == "enable" else ("FAIL" if banner == "disable" or not command_failed(global_cfg) else "NOT_EVALUATED"),
        "El pre-login banner está habilitado." if banner == "enable" else "El pre-login banner está deshabilitado o el valor no se pudo leer.",
        f"pre-login-banner={banner or 'no observado'}", FORTI_BENCHMARK))

    ntp_config = outputs.get("show full-configuration system ntp", "")
    ntp_enabled = bool(re.search(r"(?im)^\s*(?:set\s+)?ntpsync\s*(?::|\s)\s*(?:enable|enabled|1)\b", ntp_config))
    ntp_status_known = not command_failed(ntp) and not command_failed(ntp_config)
    ntp_ok = bool(ntp_enabled and re.search(r"synchronized\s*:\s*yes", ntp, re.I))
    controls.append(control_result("2.1.4", "Ensure correct system time is configured through NTP", "PASS" if ntp_ok else ("FAIL" if ntp_status_known else "NOT_EVALUATED"),
        "NTP aparece habilitado y sincronizado." if ntp_ok else "No se confirmó sincronización NTP activa.",
        f"ntpsync={'habilitado' if ntp_enabled else 'no confirmado'}; " + re.sub(r"(?im)^.*(?:reference time|server-version).*$", "<detalle de tiempo omitido>", ntp.strip())[:240], FORTI_BENCHMARK))

    hostname_match = re.search(r"(?im)^\s*Hostname\s*:\s*(\S+)", status)
    hostname = hostname_match.group(1).strip('"') if hostname_match else forti_value(global_cfg, "hostname")
    hostname_ok = bool(hostname and hostname.lower() not in {"fortigate", "fortigate-vm64", "fortigate-vm64-kvm"})
    controls.append(control_result("2.1.5", "Ensure hostname is set", "PASS" if hostname_ok else ("FAIL" if hostname or not command_failed(global_cfg) else "NOT_EVALUATED"),
        f"Hostname definido como {hostname}." if hostname_ok else "No se confirmó un hostname personalizado.",
        f"hostname={hostname or 'no observado'}", FORTI_BENCHMARK))

    threshold = forti_value(global_cfg, "admin-lockout-threshold")
    duration = forti_value(global_cfg, "admin-lockout-duration")
    try:
        lock_ok = int(threshold) <= 3 and int(duration) >= 60 and int(threshold) > 0
    except (TypeError, ValueError):
        lock_ok = False
    controls.append(control_result("2.2.2", "Ensure administrator password retries and lockout time are configured", "PASS" if lock_ok else ("FAIL" if (threshold and duration) or not command_failed(global_cfg) else "NOT_EVALUATED"),
        "Umbral de intentos no mayor a 3 y bloqueo de al menos 60 segundos." if lock_ok else "No se confirmó el umbral máximo de 3 intentos y bloqueo mínimo de 60 segundos.",
        f"admin-lockout-threshold={threshold or 'no observado'}; admin-lockout-duration={duration or 'no observado'}", FORTI_BENCHMARK))

    timeout = forti_value(global_cfg, "admintimeout")
    try:
        timeout_ok = 0 < int(timeout) <= 5
    except (TypeError, ValueError):
        timeout_ok = False
    controls.append(control_result("2.4.4", "Ensure idle timeout time is configured", "PASS" if timeout_ok else ("FAIL" if timeout or not command_failed(global_cfg) else "NOT_EVALUATED"),
        "Tiempo de inactividad de administración de hasta 5 minutos." if timeout_ok else "No se confirmó un tiempo de inactividad de administración de hasta 5 minutos.",
        f"admintimeout={timeout or 'no observado'} minutos", FORTI_BENCHMARK))

    allowaccess = re.findall(r"(?im)^\s*set allowaccess\s+(.+)$", interfaces)
    clear_access = []
    for value in allowaccess:
        if re.search(r"\b(?:http|telnet)\b", value, re.I):
            clear_access.append(value.strip())
    encrypted_ok = bool(allowaccess) and not clear_access
    controls.append(control_result("2.4.5", "Ensure only encrypted access channels are enabled", "FAIL" if clear_access else ("PASS" if encrypted_ok else ("FAIL" if not command_failed(interfaces) else "NOT_EVALUATED")),
        "No se observaron HTTP/Telnet en los allowaccess de interfaz." if encrypted_ok else ("Se observó HTTP/Telnet en allowaccess." if clear_access else "No se pudo evaluar allowaccess en interfaces."),
        f"Interfaces allowaccess observadas: {len(allowaccess)}; no se cambia ninguna interfaz.", FORTI_BENCHMARK))

    services = re.findall(r"(?im)^\s*set service\s+(.+)$", policies)
    all_service = [value.strip() for value in services if re.search(r"(?:^|\s)[\"']?ALL[\"']?(?:$|\s)", value, re.I)]
    controls.append(control_result("3.2", "Ensure that policies do not use ALL as Service", "FAIL" if all_service else ("PASS" if services else ("FAIL" if not command_failed(policies) else "NOT_EVALUATED")),
        "Ninguna política observada usa ALL como servicio." if services and not all_service else ("Una o más políticas usan ALL como servicio." if all_service else "No se encontraron servicios de política para evaluar."),
        f"Políticas con set service: {len(services)}; políticas ALL: {len(all_service)}.", FORTI_BENCHMARK))
    return controls


def connect(device, username, password):
    return ConnectHandler(device_type=device["device_type"], host=device["host"], port=device.get("port", 22),
                          username=username, password=password, conn_timeout=8, banner_timeout=10,
                          auth_timeout=10, ssh_strict=True, system_host_keys=True, fast_cli=False)


def explain_connection_error(exc):
    message = str(exc).lower()
    if "no acceptable kex algorithm" in message:
        return ("El cliente y el IOS no comparten algoritmo de intercambio SSH. En IOS 15.2 antiguo, "+
                "comprueba primero la oferta con ssh -vvv; Paramiko 4 quitó KEX basados en SHA-1. "+
                "No cambies algoritmos del equipo sin confirmar lo que ofrece.")
    if "authentication" in message or "auth" in message:
        return "SSH sí respondió, pero rechazó la cuenta. Usa la cuenta propia de este dispositivo; no asumas que es 'auditor'."
    if isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in message:
        return "No se completó la conexión SSH. Comprueba TCP/22, la política FortiGate entre port3 y port2, y que SSH esté habilitado en el equipo."
    if "known_hosts" in message or "host key" in message:
        return "La clave del equipo no está aceptada en known_hosts. Verifica que la IP sea el equipo esperado y acepta su clave desde Kali."
    return "Revisa el mensaje de error y confirma que la IP, el puerto y el acceso SSH del dispositivo sean correctos."


def scan(phase, credentials, evidence_dir, mode="AUDIT_ONLY"):
    devices = []
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for device in DEVICES:
        result = {"id": device["id"], "name": device["name"], "host": device["host"],
                  "connectivity": "ERROR", "controls": [], "commands": []}
        if not device["host"]:
            result["error"] = "Completa la IP de administración en DEVICES dentro del script."
            devices.append(result)
            continue
        try:
            with socket.create_connection((device["host"], device.get("port", 22)), timeout=4):
                result["tcp"] = "PASS"
            username, password = credentials[device["id"]]
            session = connect(device, username, password)
            try:
                result["connectivity"] = "PASS"
                evidence_path = evidence_dir / f"{device['id']}_evidence.txt"
                outputs = {}
                evidence_fd = os.open(evidence_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(evidence_fd, "w", encoding="utf-8") as evidence:
                    for command in COMMANDS[device["adapter"]]:
                        output = session.send_command(command, read_timeout=20)
                        outputs[command] = output
                        evidence.write(f"$ {command}\n{redact(output)}\n\n")
                        result["commands"].append(command)
                if device["adapter"].startswith("cisco_"):
                    config = outputs.get("show running-config", "")
                    version_match = re.search(r"(?im)^.*\bVersion\s+([^,\s]+)", outputs.get("show version", ""))
                    result["observed_software"] = version_match.group(1) if version_match else "No identificado en show version"
                    result["controls"] = assess_cisco_controls(
                        config, outputs.get("show ip ssh", ""), outputs.get("show ip http server status", "")
                    )
                elif device["adapter"] == "fortigate_7_0_9":
                    version_match = re.search(r"(?im)^\s*Version:\s*(.+)$", outputs.get("get system status", ""))
                    result["observed_software"] = version_match.group(1).strip() if version_match else "No identificado en get system status"
                    result["controls"] = assess_forti_controls(outputs)
                result["evidence_file"] = str(evidence_path)
            finally:
                session.disconnect()
        except Exception as exc:
            result["connectivity"] = "ERROR"
            result["error"] = f"{exc.__class__.__name__}: {exc}"
            result["diagnosis"] = explain_connection_error(exc)
        devices.append(result)
    return {"phase": phase, "started_at": datetime.now(timezone.utc).isoformat(), "mode": mode, "devices": devices}


def private_backup(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def find_control(scan_result, device_id, control_id):
    device = next((d for d in scan_result["devices"] if d["id"] == device_id), None)
    return next((c for c in device["controls"] if c["control_id"] == control_id), None) if device else None


def build_apply_plans(device, credentials, pre, secret_values):
    """Return reviewed, reversible plans plus a private pre-change backup."""
    username, password = credentials[device["id"]]
    session = connect(device, username, password)
    try:
        plans, backup_parts = [], []
        if device["adapter"].startswith("cisco_"):
            config = session.send_command("show running-config", read_timeout=30)
            if command_failed(config):
                raise RuntimeError("No se pudo capturar show running-config; no se aplicará nada a este equipo.")
            backup_parts.append("$ show running-config\n" + config)
            statuses = {c["control_id"]: c["status"] for c in find_device(pre, device["id"])["controls"]}
            if statuses.get("1.1.4.1") == "FAIL":
                old = re.search(r"(?im)^\s*enable\s+secret\s+(.+)$", config)
                restore = ["enable secret " + old.group(1).strip()] if old else ["no enable secret"]
                plans.append({"control_id": "1.1.4.1", "title": "Enable Secret", "commands": ["enable secret " + secret_values[device["id"]]], "rollback": restore, "adapter": "cisco"})
            if statuses.get("1.1.3.3") == "FAIL":
                plans.append({"control_id": "1.1.3.3", "title": "Banner MOTD", "commands": ["banner motd #AVISO: Acceso exclusivo a usuarios autorizados. La actividad puede ser supervisada.#"], "rollback": ["no banner motd"], "adapter": "cisco"})
            if statuses.get("1.1.2.4") == "FAIL":
                blocks = cisco_vty_blocks(config)
                commands, rollback = [], []
                for block in blocks:
                    timeout = re.search(r"^exec-timeout\s+(\d+)\s+(\d+)$", "\n".join(block["lines"]), re.I | re.M)
                    minutes, seconds = (int(timeout.group(1)), int(timeout.group(2))) if timeout else (10, 0)
                    if (minutes == 0 and seconds == 0) or minutes * 60 + seconds > 600:
                        commands.extend([block["selector"], "exec-timeout 10 0"])
                        rollback.extend([block["selector"], f"exec-timeout {minutes} {seconds}" if timeout else "no exec-timeout"])
                if commands:
                    plans.append({"control_id": "1.1.2.4", "title": "Timeout VTY de 10 minutos", "commands": commands, "rollback": rollback, "adapter": "cisco"})
        else:
            global_cfg = session.send_command("get system global", read_timeout=20)
            full_global = session.send_command("show full-configuration system global", read_timeout=30)
            if command_failed(global_cfg) or command_failed(full_global):
                raise RuntimeError("No se pudo leer el estado global FortiGate; no se aplicará nada a este equipo.")
            backup_parts.extend(["$ get system global\n" + global_cfg, "$ show full-configuration system global\n" + full_global])
            statuses = {c["control_id"]: c["status"] for c in find_device(pre, device["id"])["controls"]}
            def forti_global_plan(control_id, title, values):
                if statuses.get(control_id) != "FAIL":
                    return
                old_values = {key: forti_value(global_cfg, key) for key in values}
                if any(value is None for value in old_values.values()):
                    return
                set_lines = [f"set {key} {value}" for key, value in values.items()]
                restore_lines = [f"set {key} {value}" for key, value in old_values.items()]
                plans.append({"control_id": control_id, "title": title,
                    "commands": ["config system global", *set_lines, "end"],
                    "rollback": ["config system global", *restore_lines, "end"], "adapter": "fortinet"})
            forti_global_plan("2.1.1", "Habilitar pre-login banner", {"pre-login-banner": "enable"})
            forti_global_plan("2.2.2", "Configurar bloqueo admin (3 intentos / 60 s)", {"admin-lockout-threshold": "3", "admin-lockout-duration": "60"})
            forti_global_plan("2.4.4", "Configurar timeout admin de 5 min", {"admintimeout": "5"})
            if statuses.get("2.1.5") == "FAIL":
                old_name = forti_value(global_cfg, "hostname")
                if old_name:
                    plans.append({"control_id": "2.1.5", "title": "Hostname FW1", "commands": ["config system global", "set hostname FW1", "end"], "rollback": ["config system global", f"set hostname {old_name}", "end"], "adapter": "fortinet"})
        return plans, "\n\n".join(backup_parts)
    finally:
        session.disconnect()


def find_device(scan_result, device_id):
    return next(d for d in scan_result["devices"] if d["id"] == device_id)


def send_plan(device, credentials, commands, adapter):
    username, password = credentials[device["id"]]
    session = connect(device, username, password)
    try:
        if adapter == "fortinet":
            return session.send_config_set(commands, enter_config_mode=False, exit_config_mode=False, cmd_verify=False, read_timeout=30)
        return session.send_config_set(commands, read_timeout=30)
    finally:
        session.disconnect()


def save_private_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def collect_new_enable_secret(device):
    while True:
        value = getpass.getpass(f"Nuevo enable secret para {device['id']} (mínimo 12 caracteres): ")
        confirmation = getpass.getpass("Confirma el nuevo enable secret: ")
        if len(value) >= 12 and value == confirmation:
            return value
        print("No coincide o es demasiado corto. Inténtalo de nuevo.")


def perform_apply(credentials, pre, evidence_dir, backup_dir):
    plans_by_device, backups, actions = {}, {}, []
    new_secrets = {}
    for device in DEVICES:
        if device["adapter"].startswith("cisco_") and get_status(pre, device["id"], "1.1.4.1") == "FAIL":
            new_secrets[device["id"]] = collect_new_enable_secret(device)
    for device in DEVICES:
        if find_device(pre, device["id"])["connectivity"] != "PASS":
            actions.append({"device_id": device["id"], "result": "SKIPPED", "reason": "SSH no conectado en PRE; no se intentó Apply."})
            continue
        try:
            plans, backup_text = build_apply_plans(device, credentials, pre, new_secrets)
            plans_by_device[device["id"]] = plans
            if plans:
                suffix = ".cfg" if device["adapter"].startswith("cisco_") else ".txt"
                backup_path = backup_dir / f"{device['id']}_pre_apply{suffix}"
                save_private_text(backup_path, backup_text)
                backups[device["id"]] = str(backup_path)
        except Exception as exc:
            plans_by_device[device["id"]] = []
            actions.append({"device_id": device["id"], "result": "ERROR", "reason": f"No se pudo preparar/respaldar: {exc.__class__.__name__}: {exc}"})
    flattened = [(device, plan) for device in DEVICES for plan in plans_by_device.get(device["id"], [])]
    supported = {(device["id"], plan["control_id"]) for device, plan in flattened}
    for device in DEVICES:
        for control in find_device(pre, device["id"])["controls"]:
            if control["status"] == "FAIL" and control["control_id"] not in APPLY_CONTROL_IDS:
                actions.append({"device_id": device["id"], "control_id": control["control_id"], "result": "SKIPPED", "reason": "Requiere decisión manual o datos de red; no se modifica automáticamente."})
            elif control["status"] == "FAIL" and (device["id"], control["control_id"]) not in supported:
                actions.append({"device_id": device["id"], "control_id": control["control_id"], "result": "SKIPPED", "reason": "No se pudo determinar el valor anterior para una reversión segura."})
    if not flattened:
        return pre, pre, actions
    print("\nCambios preparados (solo running-config):")
    for device, plan in flattened:
        print(f"- {device['id']} / {plan['control_id']}: {plan['title']}")
    print("Se respaldarán de forma privada las secciones afectadas antes de modificar. No se tocará FortiGate port1 ni se guardará startup-config automáticamente.")
    if input("Escribe APPLY para ejecutar estos cambios: ").strip() != "APPLY":
        return pre, pre, actions + [{"result": "CANCELLED", "reason": "El usuario canceló; no se enviaron cambios."}]
    applied_plans = []
    for device, plan in flattened:
        try:
            output = send_plan(device, credentials, plan["commands"], plan["adapter"])
            save_private_text(evidence_dir / f"{device['id']}_{plan['control_id'].replace('.', '_')}_apply.txt", redact(output))
            applied_plans.append((device, plan))
            actions.append({"device_id": device["id"], "control_id": plan["control_id"], "title": plan["title"], "result": "APPLIED", "backup_file": backups[device["id"]], "persistence": "running-config; no se ejecutó write memory"})
        except Exception as exc:
            rollback_status = "not attempted"
            try:
                send_plan(device, credentials, plan["rollback"], plan["adapter"])
                rollback_status = "sent after apply error"
            except Exception as rollback_exc:
                rollback_status = f"ERROR: {rollback_exc.__class__.__name__}"
            actions.append({"device_id": device["id"], "control_id": plan["control_id"], "title": plan["title"], "result": "ERROR", "error": exc.__class__.__name__, "rollback": rollback_status, "backup_file": backups[device["id"]]})
    post = scan("POST", credentials, evidence_dir / "POST", mode="APPLY_WORKFLOW")
    rollback_used = False
    for device, plan in applied_plans:
        action = next(a for a in reversed(actions) if a.get("device_id") == device["id"] and a.get("control_id") == plan["control_id"] and a.get("result") == "APPLIED")
        if get_status(post, device["id"], plan["control_id"]) == "PASS":
            action["post_check"] = "PASS"
            continue
        try:
            output = send_plan(device, credentials, plan["rollback"], plan["adapter"])
            save_private_text(evidence_dir / f"{device['id']}_{plan['control_id'].replace('.', '_')}_rollback.txt", redact(output))
            action["result"] = "ROLLED_BACK"
            action["rollback"] = "Enviada porque el control no pasó la verificación POST."
            rollback_used = True
        except Exception as exc:
            action["rollback"] = f"ERROR: {exc.__class__.__name__}; usa el respaldo privado {backups[device['id']]}"
    if rollback_used:
        post = scan("POST", credentials, evidence_dir / "POST_after_rollback", mode="APPLY_WORKFLOW")
    return pre, post, actions


def build_suggestions(scan_result):
    suggestions = []
    cisco_commands = {
        "1.1.2.4": "En cada línea VTY: exec-timeout 10 0 (ajustar solo las líneas que superen 10 minutos).",
        "1.1.4.1": "enable secret <CLAVE_NUEVA>; el modo Apply la pedirá sin mostrarla ni incluirla en el informe.",
        "1.1.3.3": "banner motd #AVISO: Acceso exclusivo a usuarios autorizados. La actividad puede ser supervisada.#",
    }
    forti_commands = {
        "2.1.1": "config system global ; set pre-login-banner enable ; end",
        "2.1.5": "config system global ; set hostname FW1 ; end",
        "2.2.2": "config system global ; set admin-lockout-threshold 3 ; set admin-lockout-duration 60 ; end",
        "2.4.4": "config system global ; set admintimeout 5 ; end",
    }
    manual = {
        "1.1": "Elegir una dirección DNS aprobada para el laboratorio; no se inventa un servidor.",
        "2.1.4": "Elegir/verificar un servidor NTP alcanzable antes de cambiar la sincronización.",
        "2.4.5": "Revisar allowaccess por interfaz. port1 se conserva para no perder la gestión.",
        "3.2": "Identificar cada política que usa ALL y reemplazarlo por servicios requeridos tras revisar el tráfico.",
    }
    for device in scan_result["devices"]:
        table = cisco_commands if device["id"] in {"R1", "SW1"} else forti_commands
        for control in device["controls"]:
            if control["status"] == "PASS":
                continue
            if control["status"] == "FAIL":
                suggestion = table.get(control["control_id"], manual.get(control["control_id"], "Revisar evidencia del control y definir una corrección compatible con el laboratorio."))
                will_apply = control["control_id"] in APPLY_CONTROL_IDS and control["control_id"] in table
            else:
                suggestion = "No modificar todavía: revisar evidencia/salida del dispositivo y repetir la auditoría cuando sea evaluable."
                will_apply = False
            suggestions.append({"device_id": device["id"], "control_id": control["control_id"],
                "status": control["status"], "suggestion": suggestion,
                "available_in_apply": will_apply})
    return suggestions


def get_status(scan_result, device_id, control_id):
    for device in scan_result["devices"]:
        if device["id"] == device_id:
            for control in device["controls"]:
                if control["control_id"] == control_id:
                    return control["status"]
    return None


def compare(pre, post):
    changes = []
    for old in pre["devices"]:
        new = next((d for d in post["devices"] if d["id"] == old["id"]), {})
        changes.append({"device_id": old["id"], "control_id": "SSH-CONNECTIVITY", "pre": old["connectivity"], "post": new.get("connectivity")})
        for old_control in old["controls"]:
            new_control = next((c for c in new.get("controls", []) if c["control_id"] == old_control["control_id"]), {})
            changes.append({"device_id": old["id"], "control_id": old_control["control_id"], "pre": old_control["status"], "post": new_control.get("status")})
    return [c for c in changes if c["pre"] != c["post"]]


def write_reports(report, folder):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with (folder / "report.csv").open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(["fase", "equipo", "control", "benchmark", "estado", "detalle", "evidencia", "fuente"])
        for phase, result in report["phases"].items():
            if not result:
                continue
            for device in result["devices"]:
                writer.writerow([phase, device["id"], "SSH-CONNECTIVITY", "", device["connectivity"], device.get("error", "Conexión y evidencia"), "", ""])
                for control in device["controls"]:
                    writer.writerow([phase, device["id"], control["control_id"], control["benchmark"], control["status"], control["summary"], control.get("evidence", ""), control["source"]])
        for action in report.get("apply_actions", []):
            writer.writerow(["APPLY", action.get("device_id", ""), action.get("control_id", ""), "", action.get("result", ""), action.get("reason", action.get("title", "")) + ("; " + action["rollback"] if action.get("rollback") else ""), action.get("backup_file", ""), ""])
        for suggestion in report.get("suggested_actions", []):
            writer.writerow(["PLAN", suggestion["device_id"], suggestion["control_id"], "", suggestion["status"], suggestion["suggestion"], "", ""])
    rows = []
    for device in report["phases"][report["current_phase"]]["devices"]:
        observed = "<br><small>Detectado: " + html.escape(device.get("observed_software", "sin dato")) + "</small>"
        rows.append(f"<tr><td>{html.escape(device['id'])}</td><td>{html.escape(device['name'])}{observed}</td><td>{html.escape(device['connectivity'])}</td><td>{html.escape(device.get('error', 'Conexión y evidencia'))}</td></tr>")
        for control in device["controls"]:
            rows.append(f"<tr><td>{html.escape(device['id'])}</td><td>{html.escape(control['control_id'] + ' — ' + control['title'])}<br><small>{html.escape(control['benchmark'])}</small></td><td>{html.escape(control['status'])}</td><td>{html.escape(control['summary'])}<br><small>Evidencia: {html.escape(control.get('evidence', ''))}</small></td></tr>")
    compare_rows = "".join(f"<tr><td>{html.escape(x['device_id'])}</td><td>{html.escape(x['control_id'])}</td><td>{html.escape(str(x['pre']))}</td><td>{html.escape(str(x['post']))}</td></tr>" for x in report.get("comparison", []))
    benchmark_notes = "".join(
        "<li><strong>" + html.escape(item["title"]) + "</strong>: " + html.escape(item["scope_note"]) +
        " <a href=\"" + html.escape(item["source"], quote=True) + "\">Benchmark / CIS</a>" +
        (" · <a href=\"" + html.escape(item["version_reference"], quote=True) + "\">Nota de versión</a>" if item.get("version_reference") else "") + "</li>"
        for item in report.get("benchmarks", {}).values()
    )
    page = "<!doctype html><html lang='es'><meta charset='utf-8'><title>Informe GNS3</title><h1>Informe " + report["current_phase"] + "</h1><p>Evaluación parcial y automática de controles seleccionados. No representa certificación ni cumplimiento CIS integral. Revisa benchmark, alcance y evidencia de cada control.</p><h2>Referencias y alcance</h2><ul>" + benchmark_notes + "</ul><table border='1'><tr><th>Equipo</th><th>Control / benchmark</th><th>Estado</th><th>Detalle y evidencia</th></tr>" + "".join(rows) + "</table>"
    if report.get("apply_actions"):
        action_rows = "".join(
            "<tr><td>" + html.escape(item.get("device_id", "")) + "</td><td>" + html.escape(item.get("control_id", "")) + "</td><td>" + html.escape(item.get("result", "")) + "</td><td>" + html.escape(item.get("reason", item.get("title", ""))) + ("<br>Reversión: " + html.escape(item["rollback"]) if item.get("rollback") else "") + "</td></tr>"
            for item in report["apply_actions"]
        )
        apply_note = "Se actuó sobre running-config; startup-config no se guardó automáticamente." if report.get("safety", {}).get("configuration_changes") else "No se aplicaron cambios a la configuración."
        page += "<h2>Acciones Apply</h2><p>" + apply_note + "</p><table border='1'><tr><th>Equipo</th><th>Control</th><th>Resultado</th><th>Detalle</th></tr>" + action_rows + "</table>"
    if report.get("suggested_actions"):
        suggestion_rows = "".join(
            "<tr><td>" + html.escape(item["device_id"]) + "</td><td>" + html.escape(item["control_id"]) + "</td><td>" + html.escape(item["status"]) + "</td><td>" + html.escape(item["suggestion"]) + "</td><td>" + ("Sí" if item["available_in_apply"] else "Revisión manual") + "</td></tr>"
            for item in report["suggested_actions"]
        )
        page += "<h2>Plan de cambios sugerido (sin aplicar)</h2><p>Este plan es informativo; no se enviaron comandos de configuración.</p><table border='1'><tr><th>Equipo</th><th>Control</th><th>Estado actual</th><th>Sugerencia</th><th>Apply</th></tr>" + suggestion_rows + "</table>"
    if report.get("phases", {}).get("POST") and report.get("phases", {}).get("PRE"):
        page += "<h2>Comparación PRE / POST</h2><table border='1'><tr><th>Equipo</th><th>Control</th><th>PRE</th><th>POST</th></tr>" + (compare_rows or "<tr><td colspan='4'>Sin cambios de estado</td></tr>") + "</table>"
    (folder / "report.html").write_text(page + "</html>", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Auditor GNS3: Audit Only, plan de solo lectura o Apply/POST")
    parser.add_argument("--mode", choices=["audit", "plan", "apply"], default="audit")
    parser.add_argument("--phase", choices=["PRE", "POST"], default="PRE")
    parser.add_argument("--compare-to", type=Path)
    args = parser.parse_args()
    if not all(d["host"] for d in DEVICES):
        raise SystemExit("Falta una IP en DEVICES al inicio del archivo.")
    credentials = {}
    print("Introduce la cuenta configurada en cada equipo. Las contraseñas no se guardan en los informes.")
    for device in DEVICES:
        print(f"\n{device['id']} — {device['name']} ({device['host']})")
        credentials[device["id"]] = (
            input(f"Usuario SSH para {device['id']}: ").strip(),
            getpass.getpass(f"Contraseña SSH para {device['id']} (no se mostrará): "),
        )
    run_id = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    folder = Path("reports") / run_id
    evidence = folder / "evidence"
    if args.mode in {"audit", "plan"}:
        current = scan(args.phase, credentials, evidence)
        phases = {"PRE": None, "POST": None}
        if args.compare_to:
            phases.update(json.loads(args.compare_to.read_text(encoding="utf-8")).get("phases", {}))
        phases[args.phase] = current
        changes, actions = compare(phases["PRE"], phases["POST"]) if phases["PRE"] and phases["POST"] else [], []
        current_phase = args.phase
        suggestions = build_suggestions(current) if args.mode == "plan" else []
        if args.mode == "plan":
            print("\nPlan de cambios sugerido; no se enviarán comandos de configuración:")
            for item in suggestions:
                print(f"- {item['device_id']} / {item['control_id']} ({item['status']}): {item['suggestion']}")
                if not item["available_in_apply"]:
                    print("  Requiere revisión manual o aún no es evaluable.")
            print("Vista previa terminada: no se aplicó ninguna regla.")
    else:
        pre = scan("PRE", credentials, evidence / "PRE", mode="APPLY_WORKFLOW")
        pre, post, actions = perform_apply(credentials, pre, evidence, folder / "backups")
        phases, current_phase = {"PRE": pre, "POST": post}, "POST"
        changes = compare(pre, post)
        suggestions = []
    report = {"schema_version": 3, "run_id": run_id, "current_phase": current_phase, "phases": phases,
              "comparison": changes, "apply_actions": actions, "suggested_actions": suggestions,
              "apply_supported_controls": sorted(APPLY_CONTROL_IDS),
              "benchmarks": {"cisco": CISCO_BENCHMARK, "fortigate": FORTI_BENCHMARK},
              "compliance_statement": "Se evalúan únicamente controles automatizables seleccionados. Cisco usa CIS Cisco IOS Benchmark v2.2 (legacy/genérico) como referencia cercana para IOS 15.2 y vIOS L2; FortiGate usa CIS FortiGate 7.0.x v1.2.0, probado con 7.0.10, como referencia cercana para 7.0.9. No es certificación ni evaluación integral.",
              "safety": {"configuration_changes": any(a.get("result") in {"APPLIED", "ROLLED_BACK"} for a in actions), "fortigate_port1_changed": False,
                         "startup_config_saved": False}}
    write_reports(report, folder)
    current_devices = phases[current_phase]["devices"]
    totals = {key: sum(1 for d in current_devices for c in d["controls"] if c["status"] == key)
              for key in ("PASS", "FAIL", "NOT_EVALUATED", "ERROR")}
    print("Controles evaluados: " + ", ".join(f"{key}={value}" for key, value in totals.items()))
    print(f"Informes guardados en {folder}")


if __name__ == "__main__":
    main()
