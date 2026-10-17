// Dev check: runs the demo engine headless against the samples.
const fs = require("fs"), path = require("path"), vm = require("vm");
const mem = () => { const s = {}; return { getItem: k => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); } }; };
const ctx = { window: {}, sessionStorage: mem(), localStorage: mem(), console };
vm.createContext(ctx);
for (const f of ["samples.js", "engine.js"]) vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "assets", f), "utf8"), ctx);
const NC = ctx.window.NC, S = ctx.window.NC_SAMPLES;

const show = r => console.log(`${r.device.device_id.padEnd(11)} ${r.device.vendor.padEnd(9)} score=${r.score} P${r.pass_count} F${r.fail_count} U${r.unknown_count} risk=${r.risk_level} queue=${r.review_queue_count} redacted=${r.redactions} | ${r.device.model} | ${r.device.os_version} | ${r.device.serial}`);
const res = NC.auditFiles(S, "CIS");
res.forEach(show);
res.forEach(r => r.findings.forEach(f => console.log(`   ${r.device.device_id} ${f.rule_id} ${f.status.padEnd(7)} ${f.evidence ? "L" + f.evidence.line_number + " " + f.evidence.source_line : ""}`)));

const mk = res.find(r => r.device.vendor === "mikrotik");
console.log("\nQueue + suggestions:");
mk.review_queue.forEach(l => { const s = NC.suggestMapping(l); console.log(`   L${l.line_number} ${l.raw_line}  ->  ${s.target_field} = ${JSON.stringify(s.value)}`);
  if (s.target_field) NC.saveMapping("mikrotik", l, s.target_field, s.value); });
console.log("\nAfter re-audit:");
NC.reaudit([mk.device.device_id]).forEach(show);
console.log("\nRedaction leak check:", NC.getDevices().some(d => /Cisco123|Adm1nPass|s3cr3tRO|hx5rVt7/.test(JSON.stringify(d.findings) + JSON.stringify(d.review_queue) + d._content)) ? "LEAK" : "ok (no secrets in findings/queue)");
console.log("\nFix script (core-sw):\n" + NC.fixScript(NC.getDevice("core-sw")));
