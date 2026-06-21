"""
Génère les rapports de scan en JSON, Markdown et PDF.
PDF nécessite : pip install reportlab
"""
import json
from datetime import datetime


class ReportGenerator:
    def __init__(self, results: dict):
        self.results = results
        self.date = datetime.now().strftime("%Y-%m-%d %H:%M")

    def to_json(self) -> str:
        return json.dumps(self.results, ensure_ascii=False, indent=2)

    def to_markdown(self) -> str:
        r = self.results
        target = r.get("target", "N/A")
        score = r.get("score", 0)
        risk = r.get("risk_level", "N/A")
        stats = r.get("stats", {})
        findings = r.get("findings", [])

        lines = [
            f"# Rapport de Sécurité OWASP — {target}",
            f"\n**Date :** {self.date}  ",
            f"**Score :** {score}/100  ",
            f"**Niveau de risque :** {risk}  ",
            f"**Outils :** {', '.join(r.get('tools_used', []))}",
            "\n---\n",
            "## Résumé statistique\n",
            f"| Criticité | Nombre |",
            f"|-----------|--------|",
            f"| 🔴 Critique | {stats.get('critique', 0)} |",
            f"| 🟠 Élevé   | {stats.get('élevé', 0)} |",
            f"| 🟡 Moyen   | {stats.get('moyen', 0)} |",
            f"| 🟢 OK      | {stats.get('ok', 0)} |",
            "\n---\n",
            "## Findings détaillés\n",
        ]

        for f in findings:
            sev_icon = {"critique": "🔴", "élevé": "🟠",
                        "moyen": "🟡", "faible": "🔵", "ok": "🟢"}.get(
                f.get("statut", "ok"), "⚪")
            lines.append(f"### {sev_icon} {f.get('owasp_id')} — {f.get('nom')}")
            lines.append(f"\n- **Outil :** {f.get('outil', 'N/A')}")
            lines.append(f"- **Statut :** {f.get('statut', 'N/A')}")
            lines.append(f"- **CVSS :** {f.get('cvss', 0):.1f}")
            lines.append(f"- **Technique :** {f.get('technique', 'N/A')}")
            lines.append(f"\n**Détail :** {f.get('detail', '')}")
            if f.get("preuve"):
                lines.append(f"\n```\n{f.get('preuve')}\n```")
            if f.get("statut") != "ok":
                lines.append(f"\n**Remédiation :** {f.get('remediation', '')}")
            lines.append("\n---")

        lines.append(f"\n*Rapport généré automatiquement le {self.date}*")
        return "\n".join(lines)

    def to_pdf(self) -> bytes:
        """Génère un PDF via ReportLab."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                            Spacer, Table, TableStyle, HRFlowable)
            import io

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4,
                                    leftMargin=2*cm, rightMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)
            styles = getSampleStyleSheet()
            story = []

            r = self.results
            # Titre
            story.append(Paragraph(
                f"Rapport de Sécurité OWASP", styles["h1"]))
            story.append(Paragraph(
                f"Cible : {r.get('target', 'N/A')} — {self.date}", styles["Normal"]))
            story.append(Spacer(1, 0.5*cm))

            # Tableau résumé
            stats = r.get("stats", {})
            data = [["Indicateur", "Valeur"],
                    ["Score global", f"{r.get('score', 0)}/100"],
                    ["Niveau de risque", r.get("risk_level", "N/A")],
                    ["Critiques", str(stats.get("critique", 0))],
                    ["Élevés", str(stats.get("élevé", 0))],
                    ["Moyens", str(stats.get("moyen", 0))]]
            t = Table(data, colWidths=[8*cm, 8*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d2d2d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.8*cm))

            # Findings
            story.append(Paragraph("Findings", styles["h2"]))
            for f in r.get("findings", []):
                story.append(Paragraph(
                    f"<b>{f.get('owasp_id')} — {f.get('nom')}</b> "
                    f"[{f.get('statut','').upper()}] CVSS: {f.get('cvss', 0):.1f}",
                    styles["Normal"]))
                story.append(Paragraph(
                    f"Outil : {f.get('outil')} | {f.get('detail', '')}",
                    styles["Normal"]))
                if f.get("remediation") and f.get("statut") != "ok":
                    story.append(Paragraph(
                        f"→ {f.get('remediation')}", styles["Normal"]))
                story.append(HRFlowable(width="100%", thickness=0.5,
                                        color=colors.lightgrey))
                story.append(Spacer(1, 0.2*cm))

            doc.build(story)
            return buf.getvalue()

        except ImportError:
            # ReportLab non installé — retourner le markdown encodé
            return self.to_markdown().encode("utf-8")
