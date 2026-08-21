#!/usr/bin/env node
/**
 * pack.js
 * Signs extension/ into a .crx3 file plus an update.xml Group Policy can
 * poll for auto-updates. Called by scripts/package_extension.sh -- not
 * meant to be run directly.
 *
 * Usage: node pack.js <extensionDir> <keyFile> <distDir> <codebaseUrl>
 */

const fs = require("fs");
const path = require("path");
const ChromeExtension = require("crx");

const [, , extDir, keyFile, distDir, codebase] = process.argv;

if (!extDir || !keyFile || !distDir || !codebase) {
  console.error("Usage: node pack.js <extensionDir> <keyFile> <distDir> <codebaseUrl>");
  process.exit(1);
}

fs.mkdirSync(distDir, { recursive: true });

const crx = new ChromeExtension({
  codebase,
  privateKey: fs.readFileSync(keyFile),
});

crx
  .load(extDir)
  .then((c) => c.pack())
  .then((crxBuffer) => {
    const crxPath = path.join(distDir, "seceoknight.crx");
    const xmlPath = path.join(distDir, "update.xml");
    const updateXML = crx.generateUpdateXML();
    const appId = crx.generateAppId();

    fs.writeFileSync(crxPath, crxBuffer);
    fs.writeFileSync(xmlPath, updateXML);

    console.log("");
    console.log("=================================================");
    console.log("  Extension packaged");
    console.log("=================================================");
    console.log(`  Version:      ${crx.manifest.version}`);
    console.log(`  Extension ID: ${appId}`);
    console.log(`  CRX file:     ${crxPath} (${crxBuffer.length} bytes)`);
    console.log(`  Update XML:   ${xmlPath}`);
    console.log("");
    console.log("  Group Policy ExtensionInstallForcelist entry:");
    console.log(`  ${appId};${codebase.replace(/seceoknight\.crx$/, "update.xml")}`);
    console.log("");
  })
  .catch((err) => {
    console.error("ERROR packaging extension:", err);
    process.exit(1);
  });
