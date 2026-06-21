from fastapi import APIRouter
from fastapi.responses import Response
from datetime import datetime
from collections import Counter
from fpdf import FPDF
from cloud_db import _db

router = APIRouter()

class PDFReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 15)
        self.cell(0, 10, "Agentic IDS - Full System Report", border=0, align="C")
        self.ln(10)
        self.set_font("Helvetica", "", 10)
        self.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", border=0, align="C")
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

@router.get("/export/pdf")
async def generate_pdf_report():
    # Fetch alerts (limit 100 for report brevity)
    res = _db().table("alerts").select("*").order("timestamp", desc=True).limit(100).execute()
    alerts = res.data or []

    # Calculate basic summary stats
    total_alerts = len(alerts)
    sev_counts = Counter(str(a.get("severity", "Unknown")) for a in alerts)
    atk_counts = Counter(str(a.get("attack_type", "Unknown")) for a in alerts)

    pdf = PDFReport()
    pdf.add_page()

    # Summary Section
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Summary Statistics (Last 100 Alerts)", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Total Alerts: {total_alerts}", ln=True)
    
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 8, "By Severity:", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for k, v in sev_counts.items():
        pdf.cell(0, 6, f"  Severity {k}: {v}", ln=True)

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 8, "By Attack Type:", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for k, v in atk_counts.most_common():
        pdf.cell(0, 6, f"  {k}: {v}", ln=True)

    pdf.ln(10)

    # Alerts Table
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Recent Alerts", ln=True)
    
    # Table Header
    pdf.set_font("Helvetica", "B", 9)
    col_widths = [35, 30, 45, 20, 20, 30]
    headers = ["Timestamp", "IP", "Attack Type", "Severity", "Confidence", "Verdict"]
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 8, h, border=1)
    pdf.ln()

    # Table Rows
    pdf.set_font("Helvetica", "", 8)
    for a in alerts:
        ts = a.get("timestamp", "")
        if len(ts) > 19: ts = ts[:19].replace("T", " ")
        row = [
            ts,
            str(a.get("ip") or a.get("src_ip") or ""),
            str(a.get("attack_type") or ""),
            str(a.get("severity") or ""),
            str(a.get("confidence") or ""),
            str(a.get("verdict") or "PENDING")
        ]
        for i, val in enumerate(row):
            pdf.cell(col_widths[i], 8, str(val)[:30], border=1)
        pdf.ln()

    pdf_bytes = bytes(pdf.output())
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=ids_report.pdf"}
    )
