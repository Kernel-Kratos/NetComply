// Shared UI: nav, footer, helpers, and the logic for each demo page.
// Pages talk only to window.NC (the mock service), mirroring app/api.py -> core/service.py.
(function () {
  "use strict";

  // ---- helpers ---------------------------------------------------------------
  function h(tag, attrs) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else if (k === "value") el.value = v;
      else el.setAttribute(k, v === true ? "" : v);
    });
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  function add(el, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(el, x); }); return; }
    el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
  function $(id) { return document.getElementById(id); }
  function param(k) { return new URLSearchParams(location.search).get(k); }
  var ICON = { pass: "✓ PASS", fail: "✕ FAIL", unknown: "? UNKNOWN" };
  function status(s) { return h("span", { class: "st " + s }, ICON[s]); }
  function fmt(v) {
    if (v === null || v === undefined) return "not found";
    if (Array.isArray(v)) return v.length ? v.join(", ") : "none";
    if (v === true) return "yes";
    if (v === false) return "no";
    return String(v);
  }
  function scoreText(s) { return s === null ? "—" : s + "%"; }
  function vendorName(v) { return { cisco: "Cisco", juniper: "Juniper", mikrotik: "MikroTik", unknown: "Unknown" }[v] || v; }
  function current(id) {
    try { if (id) sessionStorage.setItem("nc.current", id); return sessionStorage.getItem("nc.current"); } catch (e) { return id; }
  }
  function pickDevice() {
    var devs = NC.getDevices(), id = param("id") || current();
    var d = (id && NC.getDevice(id)) || devs[0] || null;
    if (d) current(d.device.device_id);
    return d;
  }
  function emptyState(msg) {
    return h("div", { class: "empty" },
      h("h3", { text: "Nothing audited yet" }),
      h("p", { text: msg || "Upload a config or load the samples to start the demo." }),
      h("a", { class: "btn primary", href: "/upload/" }, "Go to Upload →"));
  }
  function download(name, text, type) {
    var url = URL.createObjectURL(new Blob([text], { type: type || "text/plain" }));
    var a = h("a", { href: url, download: name });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // ---- chrome ----------------------------------------------------------------
  var PAGE = document.body.getAttribute("data-page");
  var INFO = [["/", "Home", "home"], ["/problem/", "Problem", "problem"], ["/architecture/", "Architecture", "architecture"], ["/deliverables/", "Deliverables", "deliverables"]];
  var DEMO = [["/upload/", "Upload", "upload"], ["/dashboard/", "Dashboard", "dashboard"], ["/device/", "Device", "device"], ["/training/", "Training", "training"], ["/report/", "Report", "report"]];

  function navbar() {
    var st = NC.llmStatus();
    var badge = st.backend === "mock"
      ? h("span", { class: "badge", title: "Results come from the built-in demo engine" }, "Demo mode · no model connected")
      : h("span", { class: "badge live" }, st.model + " · " + (st.offline_mode ? "Offline" : "Online"));
    var link = function (x) { return h("a", { href: x[0], class: (x[2] === PAGE ? "on" : "") + (DEMO.indexOf(x) >= 0 ? " demo" : "") }, x[1]); };
    return h("nav", { class: "top" }, h("div", { class: "wrap" },
      h("a", { class: "logo", href: "/" }, "NETCOMPLY", h("span", {}, "AI")),
      h("div", { class: "links" }, INFO.map(link), h("span", { class: "sep" }), DEMO.map(link)),
      badge));
  }
  function progress() {
    var idx = DEMO.map(function (d) { return d[2]; }).indexOf(PAGE);
    if (idx < 0) return null;
    var id = current();
    return h("div", { class: "progress noprint" }, DEMO.map(function (d, i) {
      var href = d[0] + (id && i >= 2 ? "?id=" + encodeURIComponent(id) : "");
      return h("a", { href: href, class: i === idx ? "on" : i < idx ? "done" : "" }, h("b", {}, String(i + 1)), d[1]);
    }));
  }
  document.body.insertBefore(navbar(), document.body.firstChild);
  var prog = progress();
  if (prog && $("progress")) $("progress").appendChild(prog);
  document.body.appendChild(h("footer", {}, h("div", { class: "wrap" },
    h("span", { text: "NETCOMPLY AI · Built with Gemma 4" }),
    h("span", { text: "LLM understands · Rules judge · Evidence proves" }))));

  // ---- pages -----------------------------------------------------------------
  var pages = {};

  pages.upload = function () {
    var staged = [];
    var root = $("app");
    var fwBox = h("div", { class: "fw", role: "radiogroup", "aria-label": "Framework" }, NC.FRAMEWORKS.map(function (f) {
      return h("label", { class: f.ready ? "on" : "off", title: f.ready ? "" : "Rule set on the roadmap" },
        h("input", { type: "radio", name: "fw", value: f.id, checked: f.id === "CIS", disabled: !f.ready }),
        f.label + (f.ready ? "" : " · soon"));
    }));
    var list = h("div", {});
    var results = h("div", {});
    var runBtn = h("button", { class: "btn primary", type: "button", disabled: true, onclick: run }, "Run audit →");
    var fileInput = h("input", { type: "file", multiple: true, accept: ".cfg,.conf,.txt,.rsc,.log,.text", onchange: function (e) { readFiles(e.target.files); e.target.value = ""; } });
    var dz = h("label", { class: "dz" }, fileInput,
      h("div", { style: "font-weight:800" }, "DRAG & DROP CONFIG FILES HERE"),
      h("div", { class: "muted small", style: "margin-top:6px" }, "or click to choose · .cfg .conf .txt .rsc · single or bulk"));
    ["dragover", "dragenter"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("over"); }); });
    ["dragleave", "drop"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("over"); }); });
    dz.addEventListener("drop", function (e) { readFiles(e.dataTransfer.files); });

    var pasteName = h("input", { class: "field", type: "text", placeholder: "file name, e.g. lab-switch.cfg" });
    var pasteBox = h("textarea", { placeholder: "Paste a running-config here…", "aria-label": "Pasted configuration" });

    function readFiles(fl) {
      Array.prototype.forEach.call(fl, function (f) {
        var r = new FileReader();
        r.onload = function () { stage({ filename: f.name, content: String(r.result) }); };
        r.readAsText(f);
      });
    }
    function stage(f) {
      if (!f.content.trim()) return;
      staged = staged.filter(function (s) { return s.filename !== f.filename; }).concat([f]);
      renderList();
    }
    function renderList() {
      list.replaceChildren();
      runBtn.disabled = !staged.length;
      if (!staged.length) { list.appendChild(h("p", { class: "muted small", text: "No files added yet." })); return; }
      list.appendChild(h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "File"), h("th", {}, "Lines"), h("th", {}, ""))),
        h("tbody", {}, staged.map(function (s) {
          return h("tr", {}, h("td", {}, h("code", { text: s.filename })), h("td", { text: String(s.content.split("\n").length) }),
            h("td", {}, h("button", { class: "btn sm", type: "button", onclick: function () { staged = staged.filter(function (x) { return x !== s; }); renderList(); } }, "Remove")));
        })))));
    }
    function run() {
      var fw = (root.querySelector("input[name=fw]:checked") || {}).value || "CIS";
      runBtn.disabled = true; runBtn.textContent = "Auditing…";
      setTimeout(function () {
        var res = NC.auditFiles(staged, fw);
        if (res[0]) current(res[0].device.device_id);
        runBtn.textContent = "Run audit →"; runBtn.disabled = false;
        results.replaceChildren(
          h("h2", { text: "Detected devices", style: "margin-top:36px" }),
          h("div", { class: "table-wrap" }, h("table", {},
            h("thead", {}, h("tr", {}, ["File", "Vendor", "Model", "OS", "Serial", "Secrets hidden", "Needs review"].map(function (t) { return h("th", { text: t }); }))),
            h("tbody", {}, res.map(function (r) {
              var d = r.device;
              return h("tr", {}, h("td", {}, h("code", { text: d.filename })), h("td", { text: vendorName(d.vendor) }),
                h("td", { text: d.model || "—" }), h("td", { text: d.os_version || "—" }), h("td", { text: d.serial || "—" }),
                h("td", { text: String(r.redactions) }), h("td", { text: r.review_queue_count ? r.review_queue_count + " lines" : "—" }));
            })))),
          h("p", { class: "note", text: "Passwords, keys and SNMP strings are hidden before any analysis. Nothing leaves this browser." }),
          h("div", { class: "row end" }, h("a", { class: "btn primary", href: "/dashboard/" }, "Open dashboard →")));
        results.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 350);
    }

    root.append(
      h("div", { class: "card" },
        h("label", { class: "lbl", text: "1 · Choose framework" }), fwBox,
        h("label", { class: "lbl", text: "2 · Add configuration files", style: "margin-top:22px" }), dz,
        h("div", { class: "row", style: "margin-top:14px" },
          h("button", { class: "btn ink", type: "button", onclick: function () { NC_SAMPLES.forEach(stage); } }, "Load 3 sample configs"),
          h("span", { class: "muted small", text: "Cisco IOS · Juniper SRX · MikroTik (unseen vendor)" })),
        h("details", { style: "margin-top:18px" },
          h("summary", { class: "lbl", style: "cursor:pointer" }, "Or paste a config"),
          h("div", { style: "display:grid; gap:10px; margin-top:10px" }, pasteName, pasteBox,
            h("div", {}, h("button", { class: "btn sm", type: "button", onclick: function () {
              stage({ filename: pasteName.value.trim() || "pasted-" + (staged.length + 1) + ".cfg", content: pasteBox.value });
              pasteBox.value = ""; pasteName.value = "";
            } }, "Add pasted config")))),
        h("label", { class: "lbl", text: "3 · Files to audit", style: "margin-top:22px" }), list,
        h("div", { class: "row between", style: "margin-top:22px" },
          h("button", { class: "btn sm", type: "button", onclick: function () {
            NC.resetDemo(); staged = []; renderList(); results.replaceChildren(h("p", { class: "note", text: "Demo reset: learned mappings and results cleared." }));
          } }, "Reset demo"),
          runBtn)),
      results);
    renderList();
  };

  pages.dashboard = function () {
    var root = $("app"), devs = NC.getDevices();
    if (!devs.length) { root.appendChild(emptyState()); return; }
    var sortKey = "score", dir = 1;
    var scored = devs.filter(function (d) { return d.score !== null; });
    var avg = scored.length ? Math.round(scored.reduce(function (a, d) { return a + d.score; }, 0) / scored.length) : null;
    var sum = function (k) { return devs.reduce(function (a, d) { return a + d[k]; }, 0); };
    root.appendChild(h("div", { class: "stats" },
      [["Devices", devs.length], ["Average score", scoreText(avg)], ["Failed checks", sum("fail_count")],
       ["Unknown (not counted)", sum("unknown_count")], ["Lines to review", sum("review_queue_count")]].map(function (s) {
        return h("div", {}, h("div", { class: "k", text: s[0] }), h("div", { class: "v", text: String(s[1]) }));
      })));
    var cols = [["device", "Device"], ["vendor", "Vendor"], ["score", "Score"], ["pass_count", "Pass"], ["fail_count", "Fail"], ["unknown_count", "Unknown"], ["risk", "Risk"], ["review_queue_count", "To review"]];
    var rank = { low: 1, medium: 2, high: 3, critical: 4 };
    var val = function (d, k) {
      if (k === "device") return d.device.hostname || d.device.filename;
      if (k === "vendor") return d.device.vendor;
      if (k === "risk") return rank[d.risk_level];
      if (k === "score") return d.score === null ? -1 : d.score;
      return d[k];
    };
    var wrap = h("div", {});
    function render() {
      var rows = devs.slice().sort(function (a, b) { var x = val(a, sortKey), y = val(b, sortKey); return (x > y ? 1 : x < y ? -1 : 0) * dir; });
      wrap.replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, cols.map(function (c) {
          return h("th", { "aria-sort": c[0] === sortKey ? (dir > 0 ? "ascending" : "descending") : "none" },
            h("button", { type: "button", onclick: function () { dir = sortKey === c[0] ? -dir : 1; sortKey = c[0]; render(); } },
              c[1] + (c[0] === sortKey ? (dir > 0 ? " ↑" : " ↓") : "")));
        }))),
        h("tbody", {}, rows.map(function (d) {
          var id = d.device.device_id, go = function () { location.href = "/device/?id=" + encodeURIComponent(id); };
          return h("tr", { class: "click", tabindex: "0", onclick: go, onkeydown: function (e) { if (e.key === "Enter") go(); } },
            h("td", {}, h("strong", { text: d.device.hostname || d.device.filename }), h("div", { class: "muted small", text: d.device.filename })),
            h("td", { text: vendorName(d.device.vendor) }),
            h("td", {}, h("strong", { class: "mono", text: scoreText(d.score) })),
            h("td", { text: String(d.pass_count) }), h("td", { text: String(d.fail_count) }), h("td", { text: String(d.unknown_count) }),
            h("td", {}, h("span", { class: "sev", text: d.fail_count ? d.risk_level : "—" })),
            h("td", {}, d.review_queue_count
              ? h("a", { class: "btn sm primary", href: "/training/?id=" + encodeURIComponent(id), onclick: function (e) { e.stopPropagation(); } }, d.review_queue_count + " · Train")
              : "—"));
        })))));
    }
    root.appendChild(wrap);
    root.appendChild(h("p", { class: "note", text: "Score = passed ÷ (passed + failed). Unknown checks are shown separately and never count as a pass. Click a row for details." }));
    render();
  };

  pages.device = function () {
    var root = $("app"), d = pickDevice();
    if (!d) { root.appendChild(emptyState()); return; }
    var dev = d.device, id = dev.device_id;
    var sel = h("select", { "aria-label": "Choose device", onchange: function (e) { location.href = "/device/?id=" + encodeURIComponent(e.target.value); } },
      NC.getDevices().map(function (x) { return h("option", { value: x.device.device_id, selected: x.device.device_id === id }, (x.device.hostname || x.device.filename) + " · " + vendorName(x.device.vendor)); }));
    root.append(
      h("div", { class: "row between", style: "margin-bottom:20px" },
        h("div", { style: "min-width:240px" }, sel),
        h("div", { class: "row" },
          d.review_queue_count ? h("a", { class: "btn", href: "/training/?id=" + encodeURIComponent(id) }, "Review " + d.review_queue_count + " lines") : null,
          h("a", { class: "btn primary", href: "/report/?id=" + encodeURIComponent(id) }, "Report →"))),
      h("div", { class: "stats" },
        [["Vendor", vendorName(dev.vendor), true], ["Model", dev.model || "—", true], ["OS", dev.os_version || "—", true], ["Serial", dev.serial || "—", true]].map(function (s) {
          return h("div", {}, h("div", { class: "k", text: s[0] }), h("div", { class: "v sm", text: s[1] }));
        })),
      h("div", { class: "stats" },
        [["Score", scoreText(d.score)], ["Pass", d.pass_count], ["Fail", d.fail_count], ["Unknown", d.unknown_count], ["Risk", d.fail_count ? d.risk_level.toUpperCase() : "—"]].map(function (s) {
          return h("div", {}, h("div", { class: "k", text: s[0] }), h("div", { class: "v", text: String(s[1]) }));
        })),
      h("h2", { text: "Findings · " + d.framework }),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Control", "Result", "Severity", "Ref", "Found value", "Evidence"].map(function (t) { return h("th", { text: t }); }))),
        h("tbody", {}, d.findings.map(function (f) {
          var e = f.evidence;
          return h("tr", {},
            h("td", {}, h("strong", { text: f.title }), h("div", { class: "muted small mono", text: f.rule_id })),
            h("td", {}, status(f.status)),
            h("td", {}, h("span", { class: "sev", text: f.severity })),
            h("td", { class: "small", text: "CIS · ref pending" }),
            h("td", { class: "small", text: fmt(f.observed_value) }),
            h("td", {}, e ? [h("code", { text: "L" + e.line_number + "  " + e.source_line }), h("span", { class: "origin", text: e.origin === "admin" ? "taught" : "known" })]
                          : h("span", { class: "muted small", text: "No matching line found" })));
        })))));

    var fixes = h("details", { class: "fix", open: true }, h("summary", {}, "View fixes · " + d.remediation.length));
    var inner = h("div", { class: "inner" });
    if (!d.remediation.length) inner.appendChild(h("p", { class: "muted", text: d.fail_count ? "No fix template for this vendor yet." : "No failed checks. Nothing to fix." }));
    d.remediation.forEach(function (r) {
      inner.appendChild(h("div", { class: "fixblock" },
        h("h3", {}, r.rule_id + " · " + r.title, h("span", { class: "origin", text: r.source === "llm" ? "generated · simulated" : "vendor template" })),
        h("pre", { text: "! " + NC.DISCLAIMER + "\n" + r.commands.join("\n") })));
    });
    if (d.remediation.length) inner.appendChild(h("button", { class: "btn sm", type: "button", onclick: function () { download(id + "_fix.txt", NC.fixScript(d)); } }, "Download fix script"));
    fixes.appendChild(inner);
    root.appendChild(fixes);
  };

  pages.training = function () {
    var root = $("app"), devs = NC.getDevices();
    if (!devs.length) { root.appendChild(emptyState()); return; }
    var withQueue = devs.filter(function (x) { return x.review_queue_count; });
    var d = pickDevice();
    if (!param("id") && withQueue.length && !d.review_queue_count) { d = withQueue[0]; current(d.device.device_id); }
    var before = { score: d.score, unknown: d.unknown_count, queue: d.review_queue_count };
    var saved = 0;

    root.appendChild(h("p", { class: "note", text: "Suggestions are simulated until a model is connected." }));
    root.appendChild(h("div", { class: "row", style: "margin-bottom:22px" },
      h("div", { style: "min-width:260px" }, h("select", { "aria-label": "Choose device", onchange: function (e) { location.href = "/training/?id=" + encodeURIComponent(e.target.value); } },
        devs.map(function (x) { return h("option", { value: x.device.device_id, selected: x.device.device_id === d.device.device_id }, (x.device.hostname || x.device.filename) + " · " + x.review_queue_count + " to review"); }))),
      h("span", { class: "muted small", text: "Lines the system did not recognize for " + vendorName(d.device.vendor) + "." })));

    if (!d.review_queue_count) {
      root.appendChild(h("div", { class: "empty" }, h("h3", { text: "All lines understood" }),
        h("p", { text: "This device has nothing left to review." }),
        h("a", { class: "btn primary", href: "/device/?id=" + encodeURIComponent(d.device.device_id) }, "View device →")));
      return;
    }

    var fieldOpts = [["", "— no matching control —"]].concat(Object.keys(NC.FIELDS).map(function (k) { return [k, NC.FIELDS[k].label]; }));
    var plain = function (c) { return c >= 0.85 ? "likely match" : c >= 0.6 ? "possible match" : "unsure"; };

    d.review_queue.forEach(function (line) {
      var sug = NC.suggestMapping(line);
      var state = h("span", { class: "status-line", text: "Suggestion · not saved" });
      var fieldSel = h("select", { disabled: true, "aria-label": "Control" }, fieldOpts.map(function (o) { return h("option", { value: o[0], selected: o[0] === (sug.target_field || "") }, o[1]); }));
      var valueBox = h("div", {});
      function valueInput(field, v) {
        valueBox.replaceChildren();
        if (!field) { valueBox.appendChild(h("input", { class: "field", disabled: true, value: "—", "aria-label": "Value" })); return; }
        var t = NC.FIELDS[field].type, edit = !fieldSel.disabled;
        var el = t === "bool"
          ? h("select", { "aria-label": "Value", disabled: !edit }, h("option", { value: "true", selected: v === true }, "yes"), h("option", { value: "false", selected: v === false }, "no"))
          : h("input", { class: "field", "aria-label": "Value", disabled: !edit, value: Array.isArray(v) ? v.join(", ") : v === null || v === undefined ? "" : String(v), placeholder: t === "list" ? "10.0.0.5" : "10" });
        valueBox.appendChild(el);
      }
      function readValue(field) {
        var el = valueBox.firstChild, t = NC.FIELDS[field].type;
        if (t === "bool") return el.value === "true";
        if (t === "int") return parseInt(el.value, 10);
        return el.value.split(/[,\s]+/).filter(Boolean);
      }
      valueInput(sug.target_field, sug.value);
      fieldSel.addEventListener("change", function () { valueInput(fieldSel.value, null); });

      var accept = h("button", { class: "btn sm primary", type: "button" }, "Accept");
      var edit = h("button", { class: "btn sm", type: "button" }, "Edit");
      var skip = h("button", { class: "btn sm", type: "button" }, "Skip");
      var row = h("div", { class: "trow" },
        h("div", {},
          h("div", { class: "lbl", text: "Line " + line.line_number }),
          h("code", { text: line.raw_line }),
          h("div", { class: "ctx" }, h("div", { class: "muted", text: "Context" }), h("pre", { text: line.block_context }))),
        h("div", {},
          h("div", { class: "suggest" },
            h("div", { class: "tagline", text: "AI suggestion · " + plain(sug.confidence) }),
            h("div", { text: sug.rationale })),
          h("div", { class: "grid2" },
            h("div", {}, h("label", { class: "lbl", text: "Control" }), fieldSel),
            h("div", {}, h("label", { class: "lbl", text: "Value" }), valueBox)),
          h("div", { class: "row between" }, h("div", { class: "row" }, accept, edit, skip), state)));

      function finish(text) { [accept, edit, skip, fieldSel].forEach(function (b) { b.disabled = true; }); Array.prototype.forEach.call(valueBox.querySelectorAll("input,select"), function (x) { x.disabled = true; }); state.textContent = text; row.classList.add("done"); }
      edit.addEventListener("click", function () {
        fieldSel.disabled = false;
        Array.prototype.forEach.call(valueBox.querySelectorAll("input,select"), function (x) { x.disabled = false; });
        valueInput(fieldSel.value, sug.value);
        state.textContent = "Editing";
      });
      accept.addEventListener("click", function () {
        var f = fieldSel.value;
        if (!f) { finish("Skipped · no control"); return; }
        var v = readValue(f);
        if (NC.FIELDS[f].type === "int" && isNaN(v)) { state.textContent = "Enter a number"; return; }
        NC.saveMapping(d.device.vendor, line, f, v);
        saved++; reBtn.disabled = false;
        finish("Saved ✓");
      });
      skip.addEventListener("click", function () { finish("Skipped"); });
      root.appendChild(row);
    });

    var result = h("div", {});
    var reBtn = h("button", { class: "btn primary", type: "button", disabled: true, onclick: function () {
      var vendor = d.device.vendor;
      var ids = NC.getDevices().filter(function (x) { return x.device.vendor === vendor; }).map(function (x) { return x.device.device_id; });
      NC.reaudit(ids);
      var a = NC.getDevice(d.device.device_id);
      result.replaceChildren(
        h("h2", { text: "Re-audit complete", style: "margin-top:30px" }),
        h("div", { class: "stats" },
          [["Score", scoreText(before.score) + " → " + scoreText(a.score)], ["Unknown", before.unknown + " → " + a.unknown_count],
           ["Lines to review", before.queue + " → " + a.review_queue_count], ["Mappings learned", String(saved)]].map(function (s) {
            return h("div", {}, h("div", { class: "k", text: s[0] }), h("div", { class: "delta", text: s[1] }));
          })),
        h("p", { class: "note", text: "Saved mappings now apply to every " + vendorName(vendor) + " config, with no model call needed. Re-audited " + ids.length + " device(s)." }),
        h("div", { class: "row end" },
          h("a", { class: "btn", href: "/device/?id=" + encodeURIComponent(a.device.device_id) }, "View findings"),
          h("a", { class: "btn primary", href: "/report/?id=" + encodeURIComponent(a.device.device_id) }, "Report →")));
      reBtn.disabled = true;
      result.scrollIntoView({ behavior: "smooth", block: "start" });
    } }, "Save & Re-audit");
    root.appendChild(h("div", { class: "row end", style: "margin-top:10px" }, h("span", { class: "muted small", text: "Accept at least one line, then re-audit." }), reBtn));
    root.appendChild(result);
  };

  pages.report = function () {
    var root = $("app"), d = pickDevice();
    if (!d) { root.appendChild(emptyState()); return; }
    var dev = d.device, id = dev.device_id;
    var sel = h("select", { "aria-label": "Choose device", onchange: function (e) { location.href = "/report/?id=" + encodeURIComponent(e.target.value); } },
      NC.getDevices().map(function (x) { return h("option", { value: x.device.device_id, selected: x.device.device_id === id }, x.device.hostname || x.device.filename); }));
    root.appendChild(h("div", { class: "row between noprint", style: "margin-bottom:22px" },
      h("div", { style: "min-width:220px" }, sel),
      h("div", { class: "row" },
        d.remediation.length ? h("button", { class: "btn", type: "button", onclick: function () { download(id + "_fix.txt", NC.fixScript(d)); } }, "Download fix script") : null,
        h("button", { class: "btn primary", type: "button", onclick: function () { document.title = id + "_report"; window.print(); } }, "Download PDF"))));
    root.appendChild(h("p", { class: "note noprint", text: "Download PDF opens your browser's print dialog: choose “Save as PDF”. The full app builds this report with ReportLab." }));

    var meta = [["Device", dev.hostname || "—"], ["Vendor", vendorName(dev.vendor)], ["Model", dev.model || "—"], ["OS version", dev.os_version || "—"],
      ["Serial", dev.serial || "—"], ["Framework", d.framework], ["Score", scoreText(d.score)], ["Risk", d.fail_count ? d.risk_level.toUpperCase() : "—"],
      ["Pass / Fail", d.pass_count + " / " + d.fail_count], ["Unknown", d.unknown_count + " (not counted)"], ["Source file", dev.filename], ["Generated", new Date().toISOString().slice(0, 10)]];
    var rep = h("div", { class: "report" },
      h("div", { class: "row between" }, h("div", { class: "logo" }, "NETCOMPLY", h("span", {}, "AI")), h("span", { class: "mono small", text: "Compliance report" })),
      h("h1", { text: dev.hostname || dev.filename, style: "margin-top:18px" }),
      h("div", { class: "meta" }, meta.map(function (m) { return h("div", {}, h("div", { class: "k", text: m[0] }), h("div", { text: m[1] })); })),
      h("h3", { text: "Findings" }),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Control", "Ref", "Result", "Severity", "Evidence"].map(function (t) { return h("th", { text: t }); }))),
        h("tbody", {}, d.findings.map(function (f) {
          return h("tr", {}, h("td", { text: f.rule_id + " · " + f.title }), h("td", { class: "small", text: "CIS · ref pending" }),
            h("td", {}, status(f.status)), h("td", {}, h("span", { class: "sev", text: f.severity })),
            h("td", {}, f.evidence ? h("code", { text: "L" + f.evidence.line_number + " " + f.evidence.source_line }) : h("span", { class: "small", text: "not found in config" })));
        })))),
      h("h3", { text: "Remediation", style: "margin-top:26px" }),
      d.remediation.length ? d.remediation.map(function (r) {
        return h("div", { class: "fixblock" }, h("h3", { text: r.rule_id + " · " + r.title + (r.source === "llm" ? " (generated, simulated)" : "") }),
          h("pre", { text: "! " + NC.DISCLAIMER + "\n" + r.commands.join("\n") }));
      }) : h("p", { text: d.fail_count ? "No fix template for this vendor yet." : "No failed controls." }),
      h("p", { class: "small", style: "margin-top:18px", text: "Unknown means the setting was not found in the configuration. It is not a pass. Framework control references are pending verification." }));
    root.appendChild(rep);
  };

  if (pages[PAGE]) pages[PAGE]();
})();
