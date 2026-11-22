#!/usr/bin/env node
/**
 * Exporta todos los _informe_pdf.html de ~/Downloads/binoracle_reports/ a PDF.
 *
 * Uso:
 *   node scripts/export_pdf.js                      # exporta todos
 *   node scripts/export_pdf.js CVE-2024-1071        # exporta solo ese CVE
 *   node scripts/export_pdf.js --out /tmp/pdfs      # directorio de salida personalizado
 *
 * Requisitos:
 *   npx puppeteer browsers install chrome
 *   (puppeteer se descarga solo la primera vez, ~170MB)
 */

const puppeteer = require("puppeteer");
const path = require("path");
const fs = require("fs");
const os = require("os");

const HTML_DIR = path.join(os.homedir(), "Downloads", "binoracle_reports");

// Parse args
const args = process.argv.slice(2);
let filterCve = null;
let outDir = HTML_DIR;

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out" && args[i + 1]) {
    outDir = args[++i];
  } else if (args[i].startsWith("CVE-") || args[i].startsWith("cve-")) {
    filterCve = args[i].toUpperCase();
  }
}

fs.mkdirSync(outDir, { recursive: true });

async function exportPdf(browser, htmlPath, pdfPath) {
  const page = await browser.newPage();
  try {
    await page.goto(`file://${htmlPath}`, { waitUntil: "networkidle0", timeout: 30000 });

    // Force white background (light theme for PDF readability)
    await page.evaluate(() => {
      document.documentElement.setAttribute("data-theme", "light");
      document.body.style.background = "#ffffff";
      // Hide sticky print bar — PDF doesn't need it
      const bar = document.querySelector(".print-bar");
      if (bar) bar.style.display = "none";
    });

    await page.pdf({
      path: pdfPath,
      format: "A4",
      printBackground: true,
      margin: { top: "18mm", bottom: "18mm", left: "16mm", right: "16mm" },
    });

    const stat = fs.statSync(pdfPath);
    console.log(`[ok]  ${path.basename(pdfPath)} — ${Math.round(stat.size / 1024)} KB`);
  } finally {
    await page.close();
  }
}

(async () => {
  const files = fs.readdirSync(HTML_DIR)
    .filter(f => f.endsWith("_informe_pdf.html"))
    .filter(f => !filterCve || f.startsWith(filterCve))
    .sort();

  if (files.length === 0) {
    console.error(`No se encontraron archivos _informe_pdf.html en ${HTML_DIR}`);
    if (filterCve) console.error(`  (filtro: ${filterCve})`);
    process.exit(1);
  }

  console.log(`Exportando ${files.length} informe(s) a PDF...`);
  console.log(`  Origen: ${HTML_DIR}`);
  console.log(`  Destino: ${outDir}`);
  console.log();

  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });

  let ok = 0, failed = 0;
  for (const file of files) {
    const htmlPath = path.join(HTML_DIR, file);
    const pdfName = file.replace("_informe_pdf.html", "_informe_pdf.pdf");
    const pdfPath = path.join(outDir, pdfName);
    try {
      await exportPdf(browser, htmlPath, pdfPath);
      ok++;
    } catch (err) {
      console.error(`[err] ${file}: ${err.message}`);
      failed++;
    }
  }

  await browser.close();

  console.log();
  console.log(`Completado: ${ok} exportados, ${failed} errores.`);
  console.log(`PDFs en: ${outDir}`);
})();
