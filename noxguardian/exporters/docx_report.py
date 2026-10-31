"""Word report generator for the audit subcommand.

Opens ``Plantilla_Informe_Auditoria_Seguridad.docx`` (path configurable via
``--template``) and fills in sections automatically from the StateManager:

  Sección 3   Identificación de equipos  -- devices, IPs, MACs, DNS PTR
  Sección 4   Inventario de servicios     -- open-port table from deep scan
  Sección 5.6 Servicios web               -- HTTP headers, TLS, CSP, HSTS
  Sección 6   Vulnerabilidades            -- draft VUL-xx cards from vuln_runner
  Sección 9   Metodología y herramientas  -- tools used, versions, commands
  Sección 10  Anexos                      -- list of every generated .txt file

Sections 1, 2, 7, 8 are left with "No verificado" because they require
human judgment (scope, authorisation, executive summary, remediation plan).

Design rules:
  * python-docx for template manipulation (import is lazy so the module
    imports without error even when python-docx is not installed).
  * All errors are captured and re-raised as ``DocxReportError`` so the
    caller can log them without crashing the audit.
  * Output / log messages in Spanish; code / docstrings in English.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..state import Device, StateManager

NO_VERIFICADO = "No verificado"


class DocxReportError(RuntimeError):
    """Raised when the .docx report cannot be generated."""


def generate(
    state: "StateManager",
    template_path: Path,
    output_path: Path,
    audit_dir: Path,
    tool_versions: Optional[Dict[str, str]] = None,
) -> Path:
    """Generate the audit Word report.

    Parameters
    ----------
    state:
        The StateManager instance after the audit has run (all modules have
        written their results into device fields).
    template_path:
        Path to the base ``.docx`` template.
    output_path:
        Destination for the generated report.
    audit_dir:
        Root of the ``noxguardian_audit_<ts>/`` folder; used to build
        relative paths for the Annex.
    tool_versions:
        Mapping of tool name -> version string for section 9.
        Example: {"nmap": "Nmap 7.94", "dig": "DiG 9.18.3", ...}

    Returns
    -------
    Path
        The path of the written ``.docx`` file.
    """
    try:
        import docx  # python-docx
    except ImportError as exc:
        raise DocxReportError(
            "python-docx no esta instalado. Ejecuta: pip install python-docx"
        ) from exc

    if not template_path.is_file():
        raise DocxReportError(
            f"plantilla no encontrada: {template_path}. "
            "Pasa la ruta correcta con --template."
        )

    try:
        doc = docx.Document(str(template_path))
    except Exception as exc:  # noqa: BLE001
        raise DocxReportError(f"no se pudo abrir la plantilla: {exc}") from exc

    devices = state.snapshot_devices()

    # Map section markers to fill functions.  Each function receives the doc
    # and adds content after the matching paragraph.
    _fill_document(doc, devices, audit_dir, tool_versions or {})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        doc.save(str(output_path))
    except Exception as exc:  # noqa: BLE001
        raise DocxReportError(f"no se pudo guardar el informe: {exc}") from exc

    return output_path


# ---------------------------------------------------------------------------
# Document-level orchestration
# ---------------------------------------------------------------------------


def _fill_document(
    doc: Any,
    devices: "List[Device]",
    audit_dir: Path,
    tool_versions: Dict[str, str],
) -> None:
    """Walk the document paragraphs and inject content at marked positions."""

    # We iterate paragraph index so we can insert after specific ones.
    # Strategy: replace placeholder text inside existing paragraphs, or
    # append tables/paragraphs after a "heading" paragraph.

    # Build content blocks keyed by the heading text fragments we look for.
    section_content: Dict[str, str] = {
        # Sections we DO fill automatically.
        "3": _build_section3(devices),
        "4": _build_section4(devices),
        "5.6": _build_section56(devices),
        "6": _build_section6(devices),
        "9": _build_section9(tool_versions),
        "10": _build_section10(audit_dir),
        # Sections left for human review.
        "1": NO_VERIFICADO,
        "2": NO_VERIFICADO,
        "7": NO_VERIFICADO,
        "8": NO_VERIFICADO,
    }

    for para in doc.paragraphs:
        text = para.text.strip()
        if not text:
            continue
        # Replace placeholder markers like <<SECCION_3>> or SECCION 3 with content.
        for key, content in section_content.items():
            marker_variants = [
                f"<<SECCION_{key}>>",
                f"<<SECCIÓN_{key}>>",
                f"[SECCION {key}]",
                f"[SECCIÓN {key}]",
                f"[CONTENIDO SECCION {key}]",
                f"[CONTENIDO SECCIÓN {key}]",
                "NO VERIFICADO",          # generic placeholder
            ]
            replaced = False
            for marker in marker_variants:
                if marker in text or (marker == "NO VERIFICADO" and text == marker):
                    _replace_para_text(para, content)
                    replaced = True
                    break
            if replaced:
                break

    # If the template has no explicit markers, append all sections at the end.
    _append_all_sections(doc, devices, audit_dir, tool_versions)


def _append_all_sections(
    doc: Any,
    devices: "List[Device]",
    audit_dir: Path,
    tool_versions: Dict[str, str],
) -> None:
    """Append a structured audit report at the end of the document.

    This is a safe fallback: even if the template uses no markers, the
    auto-generated content ends up in the document.
    """
    _add_heading(doc, "CONTENIDO AUTOGENERADO POR NOXGUARDIAN", level=1)

    _add_heading(doc, "Sección 3: Identificación de equipos", level=2)
    doc.add_paragraph(_build_section3(devices))

    _add_heading(doc, "Sección 4: Inventario de servicios y puertos", level=2)
    doc.add_paragraph(_build_section4(devices))

    _add_heading(doc, "Sección 5.6: Servicios web y cabeceras HTTP", level=2)
    doc.add_paragraph(_build_section56(devices))

    _add_heading(doc, "Sección 6: Vulnerabilidades (borrador)", level=2)
    doc.add_paragraph(_build_section6(devices))

    _add_heading(doc, "Sección 9: Metodología y herramientas", level=2)
    doc.add_paragraph(_build_section9(tool_versions))

    _add_heading(doc, "Sección 10: Anexos", level=2)
    doc.add_paragraph(_build_section10(audit_dir))


# ---------------------------------------------------------------------------
# Section builders -- return plain text blocks
# ---------------------------------------------------------------------------


def _build_section3(devices: "List[Device]") -> str:
    """Section 3: Equipment identification."""
    if not devices:
        return "No se identificaron dispositivos en la red."

    lines = ["Dispositivos identificados durante la auditoría:\n"]
    for dev in sorted(devices, key=lambda d: d.ip or ""):
        hostname = dev.hostname or dev.dns_ptr or "—"
        lines.append(
            f"  IP: {dev.ip or '—'}  |  MAC: {dev.mac_display}  |  "
            f"Fabricante: {dev.vendor}  |  Hostname/PTR: {hostname}"
        )
    return "\n".join(lines)


def _build_section4(devices: "List[Device]") -> str:
    """Section 4: Service and port inventory."""
    lines = []
    for dev in sorted(devices, key=lambda d: d.ip or ""):
        if not dev.ports:
            continue
        lines.append(f"\n[{dev.ip}] {dev.hostname or dev.vendor}")
        for record in sorted(dev.ports.values(), key=lambda r: (r.protocol, r.port)):
            status = "abierto" if record.currently_open else "cerrado"
            lines.append(
                f"  {record.protocol.upper()}/{record.port:5d}  "
                f"{record.service_label:<30}  [{status}]"
            )
    if not lines:
        return "No se realizó escaneo profundo de puertos o no se encontraron puertos abiertos."
    return "Inventario de servicios y puertos detectados:\n" + "\n".join(lines)


def _build_section56(devices: "List[Device]") -> str:
    """Section 5.6: HTTP services and security headers."""
    lines = []
    for dev in sorted(devices, key=lambda d: d.ip or ""):
        if not dev.http_headers:
            continue
        lines.append(f"\n[{dev.ip}]")
        for port_str, headers in sorted(dev.http_headers.items()):
            lines.append(f"  Puerto {port_str}:")
            lines.append(f"    Servidor          : {headers.get('server') or '—'}")
            lines.append(f"    Código de estado  : {headers.get('status_code') or '—'}")
            lines.append(f"    Redirige a HTTPS  : {'Sí' if headers.get('redirects_to_https') else 'No'}")
            lines.append(f"    HSTS              : {headers.get('hsts') or 'No presente'}")
            lines.append(f"    X-Frame-Options   : {headers.get('x_frame_options') or 'No presente'}")
            lines.append(f"    CSP               : {headers.get('csp') or 'No presente'}")
            lines.append(f"    X-Content-Type    : {headers.get('x_content_type') or 'No presente'}")
    if not lines:
        return "No se detectaron puertos web abiertos o no se realizó inspección HTTP."
    return "Resultados de inspección de cabeceras HTTP/HTTPS:\n" + "\n".join(lines)


def _build_section6(devices: "List[Device]") -> str:
    """Section 6: Vulnerability draft cards."""
    lines = []
    vuln_index = 0
    for dev in sorted(devices, key=lambda d: d.ip or ""):
        for finding in dev.vuln_findings:
            vuln_index += 1
            cves = finding.get("cves", [])
            cvss = finding.get("highest_cvss")
            service = finding.get("service", "")
            version = finding.get("version", "")

            lines.append(f"\nVUL-{vuln_index:02d}")
            lines.append(f"  Host            : {dev.ip}")
            lines.append(f"  Servicio        : {service} {version}".strip())
            lines.append(f"  CVSS máx.       : {cvss if cvss is not None else 'desconocido'}")
            if cves:
                cve_ids = ", ".join(c.get("cve_id", "") for c in cves[:5])
                lines.append(f"  CVEs            : {cve_ids}")
            sploit_hits = finding.get("searchsploit_hits", [])
            if sploit_hits:
                lines.append(f"  Exploits (DB)   : {len(sploit_hits)} encontrado(s)")
                for hit in sploit_hits[:3]:
                    lines.append(f"    - {hit}")
            lines.append(
                "  Estado          : [PENDIENTE DE REVISIÓN MANUAL — confirmar o descartar]"
            )

    if not lines:
        return (
            "No se detectaron vulnerabilidades conocidas con las herramientas utilizadas.\n"
            "Esto no descarta la existencia de vulnerabilidades no catalogadas."
        )
    header = (
        "AVISO: Las fichas siguientes son borradores generados automáticamente.\n"
        "Cada hallazgo debe ser confirmado o descartado manualmente antes de incluirlo\n"
        "en el informe final.\n"
    )
    return header + "\n".join(lines)


def _build_section9(tool_versions: Dict[str, str]) -> str:
    """Section 9: Methodology and tools."""
    lines = [
        "Metodología seguida durante la auditoría:\n",
        "1. Descubrimiento de hosts (presencia) -- nmap -sn o TCP sweep",
        "2. Inventario de puertos y versiones   -- nmap -sV -T4 -Pn",
        "3. Resolución DNS inversa              -- dig -x <ip> +short",
        "4. Inspección de cabeceras HTTP/HTTPS  -- curl -s -I -L",
        "5. Búsqueda de vulnerabilidades        -- searchsploit + NVD API v2",
        "6. Evidencia de existencia de host     -- tshark + ping",
        "",
        "Herramientas y versiones detectadas en el sistema:",
    ]
    if tool_versions:
        for tool, version in sorted(tool_versions.items()):
            lines.append(f"  {tool:<20}: {version or 'versión no detectada'}")
    else:
        lines.append("  (no se registraron versiones de herramientas)")

    lines += [
        "",
        "Nota: ningún escaneo se realizó a ciegas sobre la subred completa.",
        "Todo el tráfico se dirigió exclusivamente a los hosts confirmados como",
        "activos por el ciclo de presencia.",
    ]
    return "\n".join(lines)


def _build_section10(audit_dir: Path) -> str:
    """Section 10: Annex -- list of generated evidence files."""
    lines = ["Ficheros de evidencia generados durante la auditoría:\n"]
    if not audit_dir.exists():
        return lines[0] + "  (directorio de auditoría no encontrado)"

    # Walk the audit directory and list all .txt and .json files.
    found = sorted(audit_dir.rglob("*.txt")) + sorted(audit_dir.rglob("*.json"))
    if not found:
        return lines[0] + "  (no se encontraron ficheros de evidencia)"

    for path in found:
        try:
            rel = path.relative_to(audit_dir)
        except ValueError:
            rel = path
        lines.append(f"  {rel}")

    lines += [
        "",
        "Los ficheros .txt contienen la salida cruda de cada herramienta.",
        "El fichero audit_state.json contiene el estado consolidado de la auditoría.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# python-docx helpers
# ---------------------------------------------------------------------------


def _replace_para_text(para: Any, new_text: str) -> None:
    """Replace all runs in *para* with *new_text* preserving the first run's style."""
    if not para.runs:
        para.add_run(new_text)
        return
    first_run = para.runs[0]
    first_run.text = new_text
    for run in para.runs[1:]:
        run.text = ""


def _add_heading(doc: Any, text: str, level: int = 2) -> Any:
    """Add a heading paragraph to *doc* and return it."""
    return doc.add_heading(text, level=level)
