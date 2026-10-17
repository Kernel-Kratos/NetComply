// NetComply demo engine. Mirrors the planned backend pipeline in the browser
// (USE_MOCK_SERVICE=1 equivalent): ingest -> redact -> normalize -> rules -> remediation.
// The LLM is simulated: "suggestions" come from keyword heuristics, never from a model.
(function () {
  "use strict";

  // ---- Security Baseline Model fields --------------------------------------
  var FIELDS = {
    "management.telnet_enabled":      { label: "Telnet is enabled",            type: "bool" },
    "management.ssh_version":         { label: "SSH version",                  type: "int" },
    "management.http_server_enabled": { label: "Plain HTTP management is on",  type: "bool" },
    "management.idle_timeout_min":    { label: "Idle timeout (minutes)",       type: "int" },
    "authentication.password_encryption": { label: "Passwords stored encrypted", type: "bool" },
    "authentication.password_min_length": { label: "Minimum password length",  type: "int" },
    "snmp.default_community":         { label: "Default SNMP community in use", type: "bool" },
    "logging.syslog_servers":         { label: "Remote syslog servers",        type: "list" },
    "time.ntp_servers":               { label: "NTP servers",                  type: "list" },
    "banner.login_banner_set":        { label: "Login banner is set",          type: "bool" }
  };

  // ---- Rules (data, not code). Framework refs are placeholders until verified.
  var RULES = [
    { id: "MGMT-01", title: "Telnet disabled",                field: "management.telnet_enabled",      op: "eq",  value: false, severity: "high",   fix: "telnet" },
    { id: "MGMT-02", title: "SSH version 2 only",             field: "management.ssh_version",         op: "eq",  value: 2,     severity: "high",   fix: "ssh" },
    { id: "MGMT-03", title: "Plain HTTP management disabled", field: "management.http_server_enabled", op: "eq",  value: false, severity: "medium", fix: "http" },
    { id: "MGMT-04", title: "Idle timeout 1-10 minutes",      field: "management.idle_timeout_min",    op: "range", value: [1, 10], severity: "medium", fix: "idle" },
    { id: "AUTH-01", title: "Passwords stored encrypted",     field: "authentication.password_encryption", op: "eq", value: true, severity: "high", fix: "pwenc" },
    { id: "AUTH-02", title: "Minimum password length >= 12",  field: "authentication.password_min_length", op: "gte", value: 12, severity: "medium", fix: "pwlen" },
    { id: "SNMP-01", title: "No default SNMP community",      field: "snmp.default_community",         op: "eq",  value: false, severity: "high",   fix: "snmp" },
    { id: "LOG-01",  title: "Remote syslog configured",       field: "logging.syslog_servers",         op: "not_empty", severity: "medium", fix: "syslog" },
    { id: "TIME-01", title: "NTP configured",                 field: "time.ntp_servers",               op: "not_empty", severity: "low",    fix: "ntp" },
    { id: "BAN-01",  title: "Login banner set",               field: "banner.login_banner_set",        op: "eq",  value: true,  severity: "low",    fix: "banner" }
  ];
  var FRAMEWORKS = [
    { id: "CIS", label: "CIS Benchmarks", ready: true },
    { id: "NIST", label: "NIST SP 800-53", ready: false },
    { id: "STIG", label: "DISA STIG", ready: false },
    { id: "ISO", label: "ISO/IEC 27001", ready: false }
  ];
  var SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

  // ---- Built-in mappings: vendors the system already knows ------------------
  // field null = recognized line with no security control (not sent to review).
  var IP = "(\\d{1,3}(?:\\.\\d{1,3}){3})";
  var BUILTIN = {
    cisco: [
      [/^\s*transport input .*telnet/, "management.telnet_enabled", true],
      [/^\s*transport input (?!.*telnet)/, "management.telnet_enabled", false],
      [/^\s*ip ssh version (\d)/, "management.ssh_version", "$1"],
      [/^\s*ip http server/, "management.http_server_enabled", true],
      [/^\s*no ip http server/, "management.http_server_enabled", false],
      [/^\s*exec-timeout (\d+)/, "management.idle_timeout_min", "$1"],
      [/^\s*service password-encryption/, "authentication.password_encryption", true],
      [/^\s*no service password-encryption/, "authentication.password_encryption", false],
      [/^\s*security passwords min-length (\d+)/, "authentication.password_min_length", "$1"],
      [/^\s*snmp-server community (public|private)\b/, "snmp.default_community", true],
      [/^\s*snmp-server community <redacted>/, "snmp.default_community", false],
      [new RegExp("^\\s*logging host " + IP), "logging.syslog_servers", "ips"],
      [new RegExp("^\\s*ntp server " + IP), "time.ntp_servers", "ips"],
      [/^\s*banner (motd|login)/, "banner.login_banner_set", true],
      [/^\s*(ip http secure-server|login local|username |enable secret|snmp-server location)/, null]
    ],
    juniper: [
      [/^set system services telnet/, "management.telnet_enabled", true],
      [/^set system services ssh protocol-version v2/, "management.ssh_version", 2],
      [/^set system services web-management http(\s|$)/, "management.http_server_enabled", true],
      [/^set system login class \S+ idle-timeout (\d+)/, "management.idle_timeout_min", "$1"],
      [/encrypted-password/, "authentication.password_encryption", true],
      [/^set system login password minimum-length (\d+)/, "authentication.password_min_length", "$1"],
      [/^set snmp community (public|private)\b/, "snmp.default_community", true],
      [/^set snmp community <redacted>/, "snmp.default_community", false],
      [new RegExp("^set system syslog host " + IP), "logging.syslog_servers", "ips"],
      [new RegExp("^set system ntp server " + IP), "time.ntp_servers", "ips"],
      [/^set system login message/, "banner.login_banner_set", true],
      [/^set system services (ssh root-login|web-management https)/, null]
    ],
    mikrotik: [] // the "unseen vendor": learned through the Training page
  };

  // ---- Remediation templates (ground truth). MikroTik = simulated LLM output.
  var FIXES = {
    cisco: { wrap: ["conf t"], tail: ["end", "write memory"], source: "template", cmds: {
      telnet: ["line vty 0 4", " transport input ssh"], ssh: ["ip ssh version 2"], http: ["no ip http server"],
      idle: ["line vty 0 4", " exec-timeout 10 0"], pwenc: ["service password-encryption"],
      pwlen: ["security passwords min-length 12"], snmp: ["no snmp-server community public", "no snmp-server community private"],
      syslog: ["logging host <syslog-ip>"], ntp: ["ntp server <ntp-ip>"], banner: ["banner login ^C Authorized access only ^C"] } },
    juniper: { wrap: ["configure"], tail: ["commit"], source: "template", cmds: {
      telnet: ["delete system services telnet"], ssh: ["set system services ssh protocol-version v2"],
      http: ["delete system services web-management http"], idle: ["set system login class <class> idle-timeout 10"],
      pwlen: ["set system login password minimum-length 12"], snmp: ["delete snmp community public"],
      syslog: ["set system syslog host <syslog-ip> any any"], ntp: ["set system ntp server <ntp-ip>"],
      banner: ["set system login message \"Authorized access only\""] } },
    mikrotik: { wrap: [], tail: [], source: "llm", cmds: {
      telnet: ["/ip service disable telnet"], http: ["/ip service disable www"], ssh: ["/ip ssh set strong-crypto=yes"],
      pwlen: ["/user settings set minimum-password-length=12"], snmp: ["/snmp community set [ find name=public ] name=<new-name>"],
      syslog: ["/system logging action add name=remote target=remote remote=<syslog-ip>", "/system logging add topics=info action=remote"],
      ntp: ["/system ntp client set enabled=yes servers=<ntp-ip>"], banner: ["/system note set note=\"Authorized access only\" show-at-login=yes"] } }
  };

  var RELEVANT = /telnet|ssh|http|www|snmp|community|logging|syslog|ntp|timeout|password|banner|note|login|crypto|user|secret|service/i;

  // ---- Storage ---------------------------------------------------------------
  function load(store, key, dflt) {
    try { var v = store.getItem(key); return v ? JSON.parse(v) : dflt; } catch (e) { return dflt; }
  }
  function save(store, key, v) { try { store.setItem(key, JSON.stringify(v)); } catch (e) { /* storage unavailable */ } }
  function getDevices() { return load(sessionStorage, "nc.devices", []); }
  function setDevices(d) { save(sessionStorage, "nc.devices", d); }
  function getMappings() { return load(localStorage, "nc.mappings", []); }
  function setMappings(m) { save(localStorage, "nc.mappings", m); }

  // ---- Ingest ----------------------------------------------------------------
  function detectVendor(text) {
    if (/^set (system|version|interfaces|snmp) /m.test(text)) return "juniper";
    if (/^\/(ip|system|interface|snmp|user) /m.test(text)) return "mikrotik";
    if (/^(hostname |interface |line vty|version \d)/m.test(text)) return "cisco";
    return "unknown";
  }
  function deviceInfo(text, vendor) {
    function m(re) { var r = text.match(re); return r ? r[1].trim() : null; }
    var os = null, v;
    if (vendor === "cisco" && (v = m(/^version (\S+)/m))) os = "IOS-XE " + v;
    if (vendor === "juniper" && (v = m(/^set version (\S+)/m))) os = "Junos " + v;
    if (vendor === "mikrotik" && (v = m(/RouterOS (\S+)/))) os = "RouterOS " + v;
    return {
      model: m(/(?:Model:|model =)\s*(.+)/i),
      serial: m(/(?:Serial:|serial number =)\s*(\S+)/i),
      os_version: os,
      hostname: m(/^hostname (\S+)/m) || m(/set system host-name (\S+)/) || m(/\/system identity set name=(\S+)/)
    };
  }
  function redact(text) {
    var count = 0;
    function r(re, rep) { text = text.replace(re, function () { count++; return rep.apply(null, arguments); }); }
    r(/(encrypted-password\s+)"[^"]*"/g, function (_, k) { return k + "\"<redacted>\""; });
    r(/(^|\s)(secret|password)( \d)? (?!<redacted>|"<redacted>"|minimum-length|min-length)(\S+)/gm,
      function (_, lead, k, n) { return lead + k + (n || "") + " <redacted>"; });
    r(/(password=)(?!<redacted>)\S+/g, function (_, k) { return k + "<redacted>"; });
    r(/(community\s+)(?!public\b|private\b|<redacted>|set\b)(\S+)/g, function (_, k) { return k + "<redacted>"; });
    r(/((?:pre-shared-key|key-string)\s+)\S+/g, function (_, k) { return k + "<redacted>"; });
    return { text: text, count: count };
  }

  // ---- Normalize -------------------------------------------------------------
  function coerce(field, raw, line) {
    var t = FIELDS[field].type;
    if (raw === "ips" || t === "list") return line.match(/\d{1,3}(?:\.\d{1,3}){3}/g) || [];
    if (t === "int") return parseInt(raw, 10);
    return raw;
  }
  function applyMapping(re, field, val, line) {
    var mm = line.match(re);
    if (!mm) return null;
    var v = typeof val === "string" && val.charAt(0) === "$" ? mm[parseInt(val.slice(1), 10)] : val;
    return { field: field, value: field ? coerce(field, v, line) : null };
  }
  function normalize(lines, vendor) {
    var values = {}, queue = [];
    var learned = getMappings().filter(function (m) { return m.vendor === vendor; });
    lines.forEach(function (line, i) {
      var t = line.trim();
      if (!t || /^[!#]/.test(t) || t === "end") return;
      var hit = null, origin = "mapping";
      (BUILTIN[vendor] || []).some(function (b) { return (hit = applyMapping(b[0], b[1], b[2], line)); });
      if (!hit) {
        learned.some(function (m) {
          hit = applyMapping(new RegExp(m.line_regex), m.target_field, m.value, line);
          return hit;
        });
        if (hit) origin = "admin";
      }
      if (hit) {
        if (hit.field) {
          var prev = values[hit.field];
          var val = hit.value;
          if (FIELDS[hit.field].type === "list" && prev) val = prev.value.concat(val);
          values[hit.field] = { value: val, source_line: t, line_number: i + 1, confidence: 1, origin: origin };
        }
      } else if (RELEVANT.test(t)) {
        queue.push({ line_number: i + 1, raw_line: t, block_context: lines.slice(Math.max(0, i - 1), i + 2).join("\n") });
      }
    });
    return { values: values, queue: queue };
  }

  // ---- Compliance ------------------------------------------------------------
  function evalRule(rule, entry) {
    if (!entry || entry.value === null || entry.value === undefined) return "unknown";
    var v = entry.value;
    switch (rule.op) {
      case "eq": return v === rule.value ? "pass" : "fail";
      case "gte": return v >= rule.value ? "pass" : "fail";
      case "range": return v >= rule.value[0] && v <= rule.value[1] ? "pass" : "fail";
      case "not_empty": return Array.isArray(v) && v.length ? "pass" : "fail";
      default: throw new Error("Unsupported rule op: " + rule.op);
    }
  }

  function audit(file, framework) {
    var red = redact(file.content.replace(/\r\n/g, "\n"));
    var vendor = detectVendor(red.text);
    var lines = red.text.split("\n");
    var norm = normalize(lines, vendor);
    var findings = RULES.map(function (rule) {
      var e = norm.values[rule.field];
      return { rule_id: rule.id, title: rule.title, frameworks: { CIS: "ref pending" }, status: evalRule(rule, e),
               severity: rule.severity, field: rule.field, observed_value: e ? e.value : null, evidence: e || null, fix: rule.fix };
    });
    var pass = findings.filter(function (f) { return f.status === "pass"; }).length;
    var fail = findings.filter(function (f) { return f.status === "fail"; }).length;
    var unk = findings.length - pass - fail;
    var risk = findings.reduce(function (r, f) { return f.status === "fail" && SEV_RANK[f.severity] > SEV_RANK[r] ? f.severity : r; }, "low");
    var tpl = FIXES[vendor];
    var remediation = !tpl ? [] : findings.filter(function (f) { return f.status === "fail" && tpl.cmds[f.fix]; })
      .map(function (f) { return { rule_id: f.rule_id, title: f.title, vendor: vendor, commands: tpl.cmds[f.fix], source: tpl.source }; });
    var info = deviceInfo(red.text, vendor);
    var id = (info.hostname || file.filename).replace(/[^\w.-]/g, "_");
    return {
      device: { device_id: id, filename: file.filename, vendor: vendor, model: info.model, os_version: info.os_version,
                hostname: info.hostname, serial: info.serial },
      framework: framework, score: pass + fail ? Math.round((pass / (pass + fail)) * 100) : null, risk_level: fail ? risk : "low",
      pass_count: pass, fail_count: fail, unknown_count: unk, findings: findings, remediation: remediation,
      review_queue: norm.queue, review_queue_count: norm.queue.length, redactions: file.redactions || red.count,
      lines_total: lines.filter(function (l) { return l.trim() && !/^\s*[!#]/.test(l); }).length,
      _content: red.text // only the redacted text is kept
    };
  }

  // ---- Simulated LLM suggestions (demo mode) ---------------------------------
  function suggestMapping(line) {
    var l = line.raw_line, ips = l.match(/\d{1,3}(?:\.\d{1,3}){3}/g) || [];
    var S = function (f, v, c, why) { return { target_field: f, value: v, confidence: c, rationale: why }; };
    if (/telnet/i.test(l)) return S("management.telnet_enabled", /disabled=no|enable/i.test(l), 0.92, "Line turns the Telnet service on or off.");
    if (/\bwww\b|http(?!s)/i.test(l)) return S("management.http_server_enabled", /disabled=no/i.test(l) || !/disabled=yes/i.test(l), 0.88, "'www' is the plain-HTTP web management service.");
    if (/community/i.test(l)) return S("snmp.default_community", /\b(public|private)\b/i.test(l), 0.9, "Sets the SNMP community name; 'public' is a well-known default.");
    if (/logging|syslog/i.test(l) && ips.length) return S("logging.syslog_servers", ips, 0.9, "Sends logs to a remote server.");
    if (/ntp/i.test(l)) return S("time.ntp_servers", ips, 0.9, "Configures time synchronization servers.");
    if (/note|banner|motd|show-at-login/i.test(l)) return S("banner.login_banner_set", true, 0.8, "Text shown to users at login.");
    if (/timeout/i.test(l)) return S("management.idle_timeout_min", parseInt((l.match(/(\d+)/) || [])[1] || "0", 10), 0.7, "Sets an inactivity timeout.");
    if (/password|secret/i.test(l)) return S(null, null, 0.4, "Contains a credential (redacted). No matching control. Skip unless it sets a policy.");
    if (/ssh/i.test(l)) return S(null, null, 0.5, "Turns the SSH service on. No control checks this directly.");
    return S(null, null, 0.2, "No matching security control.");
  }

  // Turns an approved line into a reusable pattern: IPs and numbers become wildcards.
  function generalize(raw) {
    var esc = raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    esc = esc.replace(/\d{1,3}(?:\\\.\d{1,3}){3}/g, "\\d{1,3}(?:\\.\\d{1,3}){3}");
    var num = false;
    esc = esc.replace(/(^|[=\s])\d+(?=\s|$)/g, function (_, p) { num = true; return p + "(\\d+)"; });
    return { regex: "^\\s*" + esc, numCaptured: num };
  }

  function saveMapping(vendor, line, field, value) {
    var g = generalize(line.raw_line);
    var t = FIELDS[field].type;
    var stored = t === "list" ? "ips" : t === "int" && g.numCaptured ? "$1" : value;
    var maps = getMappings();
    maps.push({ id: Date.now() + "-" + maps.length, vendor: vendor, line_regex: g.regex, target_field: field,
                value: stored, sample: line.raw_line, created_by: "admin", created_at: new Date().toISOString(), active: true });
    setMappings(maps);
  }

  function auditFiles(files, framework) {
    var res = files.map(function (f) { return audit(f, framework); });
    var seen = {};
    res.forEach(function (r) { // keep ids unique
      var id = r.device.device_id, n = 1;
      while (seen[id]) id = r.device.device_id + "-" + (++n);
      seen[id] = true; r.device.device_id = id;
    });
    setDevices(res);
    return res;
  }
  function reaudit(ids) {
    var devs = getDevices().map(function (d) {
      if (ids.indexOf(d.device.device_id) < 0) return d;
      var r = audit({ filename: d.device.filename, content: d._content, redactions: d.redactions }, d.framework);
      r.device.device_id = d.device.device_id;
      return r;
    });
    setDevices(devs);
    return devs;
  }
  function getDevice(id) { return getDevices().filter(function (d) { return d.device.device_id === id; })[0] || null; }

  function fixScript(d) {
    var tpl = FIXES[d.device.vendor];
    if (!tpl || !d.remediation.length) return "";
    var out = ["! " + d.device.hostname + " - NetComply suggested fixes", "! Suggested. Review and test before applying."];
    if (tpl.source === "llm") out.push("! Generated (simulated in demo mode). No vendor template exists yet.");
    out = out.concat(tpl.wrap);
    d.remediation.forEach(function (r) { out.push("! " + r.rule_id + " " + r.title); out = out.concat(r.commands); });
    return out.concat(tpl.tail).join("\n") + "\n";
  }

  window.NC = {
    FIELDS: FIELDS, RULES: RULES, FRAMEWORKS: FRAMEWORKS, DISCLAIMER: "Suggested. Review and test before applying.",
    auditFiles: auditFiles, reaudit: reaudit, getDevices: getDevices, getDevice: getDevice,
    suggestMapping: suggestMapping, saveMapping: saveMapping, getMappings: getMappings,
    resetDemo: function () { setMappings([]); setDevices([]); }, fixScript: fixScript,
    llmStatus: function () { return { backend: "mock", model: "(none)", offline_mode: true, ready: true }; }
  };
})();
