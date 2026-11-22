#!/usr/bin/env bash
# Regenera todos los informes binoracle de principio a fin.
#
# Uso:
#   ./scripts/make_reports.sh           # pipeline completo
#   ./scripts/make_reports.sh --no-llm  # salta la generacion LLM (mas rapido)
#   ./scripts/make_reports.sh --no-pdf  # salta la exportacion a PDF
#
# Pasos:
#   1. Backfill plantilla (20 CVEs sin markdown_report -> genera desde datos)
#   2. (opcional) Genera markdown_report via LLM para todos
#   3. Genera 21 HTML con gen_informe_pdf.py
#   4. Genera index.html
#   5. Genera drafts YWH para los HUECO
#   6. (opcional) Exporta 21 PDF con Puppeteer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GEN_SCRIPT="$SCRIPT_DIR/gen_informe_pdf.py"
INDEX_SCRIPT="$SCRIPT_DIR/gen_index.py"
OUT="$HOME/Downloads/binoracle_reports"
USE_LLM=true
USE_PDF=true

for arg in "$@"; do
  case "$arg" in
    --no-llm) USE_LLM=false ;;
    --no-pdf) USE_PDF=false ;;
  esac
done

echo "=== binoracle make_reports ==="
echo "    Salida: $OUT"
echo ""

# 1. Backfill plantilla (rapido, siempre)
echo "[1/6] Backfill markdown_report (plantilla) ..."
python3 "$SCRIPT_DIR/backfill_markdown_report.py"

# 2. LLM enrichment (lento, opcional)
if $USE_LLM; then
  echo ""
  echo "[2/6] Generacion LLM de markdown_report (puede tardar varios minutos) ..."
  python3 "$SCRIPT_DIR/generate_llm_reports.py"
else
  echo "[2/6] Generacion LLM omitida (--no-llm)"
fi

# 3. Generar HTMLs
echo ""
echo "[3/6] Generando 21 HTML con gen_informe_pdf.py ..."
python3 "$GEN_SCRIPT"

# 4. Index
echo ""
echo "[4/6] Generando index.html ..."
python3 "$INDEX_SCRIPT"

# 5. YWH drafts
echo ""
echo "[5/6] Generando drafts YesWeHack (HUECOs) ..."
python3 "$SCRIPT_DIR/gen_ywh_reports.py"

# 6. PDF export
if $USE_PDF; then
  echo ""
  echo "[6/6] Exportando PDFs via Puppeteer ..."
  node "$SCRIPT_DIR/export_pdf.js"
else
  echo "[6/6] Export PDF omitido (--no-pdf)"
fi

echo ""
echo "=== Completado ==="
echo "    HTML + PDF: $OUT/"
echo "    YWH drafts: $OUT/ywh/"
echo "    Index:      $OUT/index.html"
