"""
QuantumShield — Reports Endpoints

POST /api/report/executive  → generate executive summary report
POST /api/report/scheduler  → schedule a recurring report
POST /api/report/on-demand  → generate and return report immediately

Supports JSON, XML, CSV, and PDF export formats.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.db.postgres import get_pg_session
from app.db import pg_models
from app.schemas.schemas import ReportRequest, ReportResponse

router = APIRouter(tags=["Reporting"])


# ── Helpers ──────────────────────────────────────────────────────

def _build_report_payload(assets: list, crypto: list) -> Dict[str, Any]:
    """Assemble scan data into a structured dict for export."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_assets": len(assets),
        "assets": [
            {
                "asset_name": a.asset_name,
                "url": a.url,
                "ipv4": a.ipv4,
                "type": a.type,
                "risk": a.risk,
                "certificate_status": a.certificate_status,
                "key_length": a.key_length,
                "last_scan": a.last_scan.isoformat() if a.last_scan else None,
            }
            for a in assets
        ],
        "crypto_records": [
            {
                "asset": c.asset,
                "key_length": c.key_length,
                "cipher_suite": c.cipher_suite,
                "tls_version": c.tls_version,
                "certificate_authority": c.certificate_authority,
            }
            for c in crypto
        ],
    }


def _to_json(payload: Dict) -> str:
    return json.dumps(payload, indent=2)


def _to_xml(payload: Dict) -> str:
    root = ET.Element("QuantumShieldReport")
    root.set("generated_at", payload.get("generated_at", ""))
    root.set("total_assets", str(payload.get("total_assets", 0)))

    assets_el = ET.SubElement(root, "Assets")
    for a in payload.get("assets", []):
        asset_el = ET.SubElement(assets_el, "Asset")
        for k, v in a.items():
            el = ET.SubElement(asset_el, k)
            el.text = str(v) if v is not None else ""

    crypto_el = ET.SubElement(root, "CryptoRecords")
    for c in payload.get("crypto_records", []):
        record_el = ET.SubElement(crypto_el, "Record")
        for k, v in c.items():
            el = ET.SubElement(record_el, k)
            el.text = str(v) if v is not None else ""

    return ET.tostring(root, encoding="unicode", xml_declaration=False)


def _to_csv(payload: Dict) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "asset_name", "url", "ipv4", "type", "risk",
        "certificate_status", "key_length", "last_scan"
    ])
    writer.writeheader()
    writer.writerows(payload.get("assets", []))
    return output.getvalue()


def _to_pdf(payload: Dict) -> bytes:
    """Generate a simple PDF using reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph("QuantumShield — Security Assessment Report", styles["Title"]))
        story.append(Paragraph(f"Generated: {payload.get('generated_at', '')}", styles["Normal"]))
        story.append(Spacer(1, 12))

        # Assets table
        story.append(Paragraph("Asset Inventory", styles["Heading2"]))
        data = [["Asset Name", "Type", "Risk", "Key Length", "Certificate Status"]]
        for a in payload.get("assets", []):
            data.append([
                a.get("asset_name", ""),
                a.get("type", ""),
                a.get("risk", ""),
                str(a.get("key_length", "")),
                a.get("certificate_status", ""),
            ])
        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ]))
        story.append(table)
        doc.build(story)
        return buffer.getvalue()
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="reportlab is not installed. Install it: pip install reportlab",
        )


def _build_response(fmt: str, payload: Dict, report_type: str) -> Response:
    """Return a FastAPI Response with correct content-type and disposition."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"quantumshield_{report_type}_{ts}"

    if fmt == "json":
        content = _to_json(payload)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}.json"'},
        )
    elif fmt == "xml":
        content = _to_xml(payload)
        return Response(
            content=content,
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="{filename}.xml"'},
        )
    elif fmt == "csv":
        content = _to_csv(payload)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )
    elif fmt == "pdf":
        pdf_bytes = _to_pdf(payload)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported format. Use: json, xml, csv, pdf",
        )


async def _fetch_data(session: AsyncSession):
    assets = (await session.execute(select(pg_models.Asset))).scalars().all()
    crypto = (await session.execute(select(pg_models.CryptoRecord))).scalars().all()
    return assets, crypto


# ── Endpoints ────────────────────────────────────────────────────

@router.post(
    "/report/executive",
    summary="Generate an executive summary report",
    description="Returns a high-level security summary for leadership. Supports JSON, XML, CSV, PDF.",
)
async def executive_report(
    body: ReportRequest,
    session: AsyncSession = Depends(get_pg_session),
    current_user: pg_models.User = Depends(get_current_user),
):
    """Generate a formatted executive summary report and return it as a download."""
    assets, crypto = await _fetch_data(session)
    payload = _build_report_payload(assets, crypto)
    payload["report_type"] = "executive_summary"
    payload["prepared_for"] = "Executive Leadership"
    return _build_response(body.format, payload, "executive")


@router.post(
    "/report/scheduler",
    summary="Schedule a recurring report",
    description="Schedule a report at a future date/time. Accepts JSON/XML/CSV/PDF format.",
)
async def schedule_report(
    body: ReportRequest,
    session: AsyncSession = Depends(get_pg_session),
    current_user: pg_models.User = Depends(get_current_user),
):
    """
    Register a scheduled report. In production this would queue a background job.
    Returns a confirmation with the scheduled timestamp.
    """
    if not body.scheduled_at:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="'scheduled_at' is required for scheduled reports.",
        )

    # Persist report record
    report = pg_models.Report(
        type="scheduled",
        format=body.format,
        content=None,
        scheduled_at=body.scheduled_at,
        created_by=current_user.id,
    )
    session.add(report)
    await session.commit()
    await session.refresh(report)

    return {
        "message": "Report scheduled successfully.",
        "report_id": str(report.id),
        "scheduled_at": body.scheduled_at.isoformat(),
        "format": body.format,
    }


@router.post(
    "/report/on-demand",
    summary="Generate and download a report immediately",
    description="Run and return a report right now. Supports JSON, XML, CSV, PDF.",
)
async def on_demand_report(
    body: ReportRequest,
    session: AsyncSession = Depends(get_pg_session),
    current_user: pg_models.User = Depends(get_current_user),
):
    """Generate and immediately return a formatted report file."""
    assets, crypto = await _fetch_data(session)
    payload = _build_report_payload(assets, crypto)
    payload["report_type"] = "on_demand"

    # Persist a record
    report = pg_models.Report(
        type="on-demand",
        format=body.format,
        created_by=current_user.id,
    )
    session.add(report)
    await session.commit()

    return _build_response(body.format, payload, "on_demand")
