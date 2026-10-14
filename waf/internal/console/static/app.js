/* HiTechCloud WAF console. All dynamic text is inserted with textContent. */
(function () {
  "use strict";
  var KEY = "hcw-waf-token";
  var state = { sites: [], certs: [] };

  // ---------- helpers ----------
  function $(id) { return document.getElementById(id); }
  function token() { try { return sessionStorage.getItem(KEY) || ""; } catch (e) { return ""; } }
  function setToken(t) { try { if (t) sessionStorage.setItem(KEY, t); else sessionStorage.removeItem(KEY); } catch (e) {} }

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === undefined || v === null || v === false) return;
      if (k === "text") n.textContent = v;
      else if (k === "class") n.className = v;
      else if (k.slice(0, 2) === "on") n.addEventListener(k.slice(2), v);
      else if (k === "value") n.value = v;
      else if (k === "checked") n.checked = !!v;
      else n.setAttribute(k, v === true ? "" : v);
    });
    (children || []).forEach(function (c) { if (c !== null && c !== undefined) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
  function toast(msg, bad) {
    var t = $("toast"); t.textContent = msg; t.className = "toast" + (bad ? " bad" : ""); t.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(function () { t.hidden = true; }, bad ? 6000 : 2500);
  }
  function fmtTime(s) { var d = new Date(s); return isNaN(d) ? "" : d.toLocaleString("vi-VN"); }
  function lines(s) { return (s || "").split(/[\n,]+/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function nums(s) { return lines(s).map(Number).filter(function (x) { return x > 0; }); }
  function num(v, d) { var n = parseInt(v, 10); return isNaN(n) ? d : n; }

  function api(method, path, body) {
    return fetch(path, {
      method: method,
      headers: { "X-HCW-API-TOKEN": token(), "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return { err: "http_" + r.status, msg: r.statusText }; }).then(function (j) {
        if (r.status === 401) { setToken(""); show(); }
        if (!r.ok || j.err) throw new Error(j.msg || j.err || ("HTTP " + r.status));
        return j.data;
      });
    });
  }

  // ---------- shell ----------
  function show() {
    var authed = !!token();
    $("login").hidden = authed; $("app").hidden = !authed;
    if (authed) route();
  }
  $("login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    setToken($("token").value.trim());
    api("GET", "/api/open/info").then(function () { $("token").value = ""; $("login-err").textContent = ""; show(); })
      .catch(function (err) { setToken(""); $("login-err").textContent = "Token không hợp lệ: " + err.message; });
  });
  $("logout").addEventListener("click", function () { setToken(""); show(); });

  fetch("/api/open/brand").then(function (r) { return r.json(); }).then(function (j) {
    var b = j.data || {};
    if (b.name) {
      document.title = b.name + " Console";
      Array.prototype.forEach.call(document.querySelectorAll(".brand-name"), function (n) { n.textContent = b.name; });
    }
    if (b.color && /^#[0-9a-fA-F]{3,8}$/.test(b.color)) document.documentElement.style.setProperty("--brand", b.color);
  }).catch(function () {});

  function route() {
    var h = location.hash.replace(/^#\/?/, "") || "dashboard";
    var parts = h.split("/");
    Array.prototype.forEach.call(document.querySelectorAll("[data-nav]"), function (a) {
      a.classList.toggle("active", a.getAttribute("data-nav") === parts[0]);
    });
    var v = clear($("view"));
    var views = { dashboard: dashboard, sites: sites, events: eventsView, certs: certs };
    (views[parts[0]] || dashboard)(v, parts.slice(1));
  }
  window.addEventListener("hashchange", function () { if (token()) route(); });

  function loadAll() {
    return Promise.all([api("GET", "/api/open/site"), api("GET", "/api/open/cert")]).then(function (r) {
      state.sites = r[0].data || []; state.certs = r[1].data || [];
    });
  }
  function siteName(id) {
    for (var i = 0; i < state.sites.length; i++) if (state.sites[i].id === id) return state.sites[i].name;
    return "#" + id;
  }

  // ---------- dashboard ----------
  function dashboard(v) {
    v.appendChild(el("h1", { text: "Tổng quan" }));
    var cards = el("div", { class: "cards" });
    var chartCard = el("div", { class: "card" });
    var tableWrap = el("div");
    v.appendChild(cards); v.appendChild(chartCard); v.appendChild(tableWrap);
    Promise.all([loadAll(), api("GET", "/api/open/timeseries"), api("GET", "/api/open/stats"), api("GET", "/api/open/info"), api("GET", "/api/open/events?limit=200")])
      .then(function (r) {
        var series = r[1], stats = r[2] || {}, info = r[3], recent = (r[4].data || []);
        $("ver").textContent = "v" + info.version;
        var sum = function (k) { return series.reduce(function (a, b) { return a + (b[k] || 0); }, 0); };
        [["Ứng dụng", state.sites.length], ["Request (60 phút)", sum("requests")], ["Bị chặn (60 phút)", sum("blocked")],
         ["Rate limit", sum("rate_limited")], ["ACL IP", sum("acl_blocked")], ["Bot bị loại", sum("bot_failed")]]
          .forEach(function (c) { cards.appendChild(el("div", { class: "card stat" }, [el("span", { class: "muted", text: c[0] }), el("b", { text: String(c[1]) })])); });

        chartCard.appendChild(el("div", { class: "row" }, [el("b", { text: "Lưu lượng 60 phút gần nhất" }), el("span", { class: "spacer" }),
          el("span", { class: "legend" }, [el("span", {}, [el("i", { class: "lg-req" }), "Request"]), el("span", {}, [el("i", { class: "lg-blk" }), "Bị chặn"])])]));
        chartCard.appendChild(chart(series));

        // Top attack types from recent events
        var tags = {};
        recent.forEach(function (e) { (e.tags || []).forEach(function (t) { tags[t] = (tags[t] || 0) + 1; }); if (e.kind !== "waf") tags[e.kind] = (tags[e.kind] || 0) + 1; });
        var top = Object.keys(tags).sort(function (a, b) { return tags[b] - tags[a]; }).slice(0, 8);
        tableWrap.appendChild(el("h2", { text: "Loại tấn công gần đây" }));
        tableWrap.appendChild(top.length ? el("div", { class: "row" }, top.map(function (t) { return el("span", { class: "pill bad", text: t + " · " + tags[t] }); }))
          : el("p", { class: "muted", text: "Chưa có sự kiện." }));

        tableWrap.appendChild(el("h2", { text: "Theo ứng dụng (từ khi khởi động)" }));
        var tb = el("tbody");
        state.sites.forEach(function (s) {
          var c = stats[s.id] || {};
          tb.appendChild(el("tr", { class: "click", onclick: function () { location.hash = "#/sites/" + s.id; } }, [
            el("td", { text: s.name }), el("td", {}, [modePill(s.mode)]),
            el("td", { text: String(c.requests || 0) }), el("td", { text: String(c.blocked || 0) }),
            el("td", { text: String(c.monitored || 0) }), el("td", { text: String((c.rate_limited || 0) + (c.acl_blocked || 0) + (c.bot_failed || 0)) })]));
        });
        tableWrap.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, ["Ứng dụng", "Chế độ", "Request", "Chặn", "Monitor", "Rate/ACL/Bot"].map(function (h) { return el("th", { text: h }); }))]), tb])]));
      }).catch(function (e) { toast(e.message, true); });
  }

  var SVG = "http://www.w3.org/2000/svg";
  function chart(series) {
    var W = 600, H = 180, pad = 4, n = series.length;
    var max = Math.max(1, Math.max.apply(null, series.map(function (b) { return b.requests; })));
    var svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H); svg.setAttribute("preserveAspectRatio", "none"); svg.setAttribute("class", "chart");
    var bw = W / n;
    series.forEach(function (b, i) {
      var blocked = (b.blocked || 0) + (b.rate_limited || 0) + (b.acl_blocked || 0) + (b.bot_failed || 0);
      [["req", b.requests], ["blk", blocked]].forEach(function (p) {
        var h = (H - pad) * p[1] / max; if (p[1] > 0 && h < 1) h = 1;
        var r = document.createElementNS(SVG, "rect");
        r.setAttribute("x", (i * bw + 1).toFixed(1)); r.setAttribute("width", Math.max(1, bw - 2).toFixed(1));
        r.setAttribute("y", (H - h).toFixed(1)); r.setAttribute("height", h.toFixed(1)); r.setAttribute("class", p[0]);
        var t = document.createElementNS(SVG, "title");
        t.textContent = new Date(b.minute * 1000).toLocaleTimeString("vi-VN") + " – request " + b.requests + ", chặn " + blocked;
        r.appendChild(t); svg.appendChild(r);
      });
    });
    return svg;
  }
  function modePill(m) { return el("span", { class: "pill " + (m === "block" ? "ok" : m === "monitor" ? "warn" : ""), text: m === "block" ? "Chặn" : m === "monitor" ? "Giám sát" : "Tắt" }); }

  // ---------- sites ----------
  function sites(v, args) {
    loadAll().then(function () {
      if (args[0] === "new") return siteForm(v, null);
      if (args[0]) {
        var s = state.sites.filter(function (x) { return String(x.id) === args[0]; })[0];
        return s ? siteForm(v, s) : (v.appendChild(el("p", { text: "Không tìm thấy ứng dụng." })));
      }
      v.appendChild(el("div", { class: "row" }, [el("h1", { text: "Ứng dụng được bảo vệ" }), el("span", { class: "spacer" }),
        el("a", { class: "btn primary", href: "#/sites/new", text: "+ Thêm ứng dụng" })]));
      var tb = el("tbody");
      state.sites.forEach(function (s) {
        var feats = [];
        if (s.rate_limit && s.rate_limit.requests) feats.push("rate " + s.rate_limit.requests + "/" + s.rate_limit.window_sec + "s");
        if (s.bot_challenge && s.bot_challenge.enabled) feats.push("anti-bot");
        if (s.auth && s.auth.enabled) feats.push("mật khẩu");
        if ((s.ip_allow || []).length) feats.push("allowlist");
        if ((s.ip_deny || []).length) feats.push("deny " + s.ip_deny.length);
        tb.appendChild(el("tr", { class: "click", onclick: function () { location.hash = "#/sites/" + s.id; } }, [
          el("td", {}, [el("b", { text: s.name }), el("div", { class: "muted mono", text: s.server_names.join(", ") })]),
          el("td", { class: "mono", text: s.ports.join(", ") }),
          el("td", { class: "mono", text: s.upstreams.join("\n") }),
          el("td", {}, [modePill(s.mode)]),
          el("td", { text: "PL" + s.paranoia }),
          el("td", { text: feats.join(", ") || "–" })]));
      });
      if (!state.sites.length) tb.appendChild(el("tr", {}, [el("td", { colspan: "6", class: "muted", text: "Chưa có ứng dụng nào. Bấm “Thêm ứng dụng”." })]));
      v.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, ["Ứng dụng", "Cổng", "Upstream", "Chế độ", "Paranoia", "Tính năng"].map(function (h) { return el("th", { text: h }); }))]), tb])]));
    }).catch(function (e) { toast(e.message, true); });
  }

  function field(label, input, hint) { return el("div", {}, [el("label", { text: label }), input, hint ? el("div", { class: "hint", text: hint }) : null]); }
  function check(label, id, on) { return el("label", { class: "check" }, [el("input", { type: "checkbox", id: id, checked: on }), label]); }
  function select(id, options, cur) {
    return el("select", { id: id }, options.map(function (o) { var opt = el("option", { value: String(o[0]), text: o[1] }); if (String(o[0]) === String(cur)) opt.selected = true; return opt; }));
  }

  function siteForm(v, s) {
    var isNew = !s;
    s = s || { server_names: [], ports: ["80"], upstreams: [], mode: "block", paranoia: 1, anomaly_threshold: 5, rate_limit: {}, bot_challenge: {}, auth: {}, ip_allow: [], ip_deny: [], disabled_rules: [] };
    var rl = s.rate_limit || {}, bot = s.bot_challenge || {}, au = s.auth || {};
    v.appendChild(el("div", { class: "row" }, [el("h1", { text: isNew ? "Thêm ứng dụng" : "Ứng dụng: " + s.name }), el("span", { class: "spacer" }),
      el("a", { class: "btn", href: "#/sites", text: "← Danh sách" })]));
    var certOpts = [[0, "— Không dùng HTTPS —"]].concat(state.certs.map(function (c) { return [c.id, c.domains.join(", ") + " (hết hạn " + fmtTime(c.not_after) + ")"]; }));
    var form = el("form", {}, [
      el("fieldset", {}, [el("legend", { text: "Cơ bản" }), el("div", { class: "grid2" }, [
        field("Tên hiển thị", el("input", { id: "f-name", value: s.name || "" })),
        field("Tên miền", el("textarea", { id: "f-names", value: (s.server_names || []).join("\n") }), "Mỗi dòng một tên miền. Hỗ trợ *.example.com; “_” = mọi tên miền."),
        field("Cổng", el("input", { id: "f-ports", value: (s.ports || []).join(", ") }), "Ví dụ: 80, 443_ssl (cổng _ssl cần chứng chỉ)."),
        field("Upstream (server gốc)", el("textarea", { id: "f-ups", value: (s.upstreams || []).join("\n") }), "http(s)://ip:port – nhiều dòng = cân bằng tải, tự loại upstream lỗi."),
        field("Chứng chỉ HTTPS", select("f-cert", certOpts, s.cert_id || 0)),
        field("Ghi chú", el("input", { id: "f-comment", value: s.comment || "" }))])]),
      el("fieldset", {}, [el("legend", { text: "Phát hiện tấn công (OWASP CRS)" }), el("div", { class: "grid2" }, [
        field("Chế độ", select("f-mode", [["block", "Chặn"], ["monitor", "Giám sát (chỉ ghi log)"], ["off", "Tắt (proxy thuần)"]], s.mode)),
        field("Mức paranoia", select("f-pl", [[1, "1 – Cân bằng (khuyên dùng)"], [2, "2 – Chặt hơn"], [3, "3 – Nghiêm ngặt"], [4, "4 – Rất nghiêm ngặt"]], s.paranoia), "Mức 3–4 dễ chặn nhầm, cần tinh chỉnh."),
        field("Ngưỡng điểm bất thường", el("input", { id: "f-thr", type: "number", min: "1", value: s.anomaly_threshold || 5 })),
        field("Tắt rule (ID)", el("input", { id: "f-dis", value: (s.disabled_rules || []).join(", ") }), "Dùng khi bị chặn nhầm; ID lấy từ trang Sự kiện.")])]),
      el("fieldset", {}, [el("legend", { text: "Giới hạn & kiểm soát truy cập" }), el("div", { class: "grid2" }, [
        field("Rate limit: số request", el("input", { id: "f-rl", type: "number", min: "0", value: rl.requests || 0 }), "0 = tắt."),
        field("Trong (giây)", el("input", { id: "f-rlw", type: "number", min: "0", value: rl.window_sec || 60 })),
        field("Chặn trong (giây)", el("input", { id: "f-rlb", type: "number", min: "0", value: rl.block_sec || 60 })),
        field("IP cho phép (allowlist)", el("textarea", { id: "f-allow", value: (s.ip_allow || []).join("\n") }), "Nếu có, chỉ các IP/CIDR này được truy cập."),
        field("IP chặn (denylist)", el("textarea", { id: "f-deny", value: (s.ip_deny || []).join("\n") }))])]),
      el("fieldset", {}, [el("legend", { text: "Anti-bot & mật khẩu" }), el("div", { class: "grid2" }, [
        el("div", {}, [check("Bật anti-bot challenge (JS proof-of-work)", "f-bot", bot.enabled),
          field("Độ khó", el("input", { id: "f-botd", type: "number", min: "8", max: "24", value: bot.difficulty || 16 }), "16 ≈ dưới 1 giây; +1 gấp đôi thời gian."),
          field("Hiệu lực (giây)", el("input", { id: "f-bott", type: "number", value: bot.ttl_sec || 3600 })),
          field("Bỏ qua đường dẫn", el("textarea", { id: "f-botx", value: (bot.exclude_paths || []).join("\n") }), "Ví dụ /api/ cho app mobile, webhook.")]),
        el("div", {}, [check("Bật bảo vệ bằng mật khẩu", "f-auth", au.enabled),
          field(au.password_hash ? "Mật khẩu mới (để trống = giữ nguyên)" : "Mật khẩu", el("input", { id: "f-authp", type: "password", autocomplete: "new-password" }), "8–72 ký tự, lưu dạng bcrypt."),
          field("Hiệu lực (giây)", el("input", { id: "f-autht", type: "number", value: au.ttl_sec || 28800 })),
          field("Bỏ qua đường dẫn", el("textarea", { id: "f-authx", value: (au.exclude_paths || []).join("\n") }))])])]),
      el("fieldset", {}, [el("legend", { text: "Proxy nâng cao" }), el("div", { class: "grid2" }, [
        field("Host gửi lên upstream", el("input", { id: "f-uh", value: s.upstream_host || "" }), "Để trống = giữ Host của khách."),
        el("div", {}, [check("Chuyển hướng HTTP → HTTPS", "f-redir", s.redirect_https), check("Bỏ qua kiểm tra chứng chỉ upstream", "f-uins", s.upstream_insecure)])])]),
      el("div", { class: "row" }, [el("button", { type: "submit", class: "btn primary", text: isNew ? "Tạo ứng dụng" : "Lưu thay đổi" }),
        isNew ? null : el("button", { type: "button", class: "btn danger", text: "Xoá ứng dụng", onclick: function () {
          if (!confirm("Xoá ứng dụng " + s.name + "?")) return;
          api("DELETE", "/api/open/site", { ids: [s.id] }).then(function () { toast("Đã xoá"); location.hash = "#/sites"; }).catch(function (e) { toast(e.message, true); });
        } })])
    ]);
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var g = function (id) { return $(id).value; };
      var body = {
        id: s.id, name: g("f-name").trim(), server_names: lines(g("f-names")), ports: lines(g("f-ports")), upstreams: lines(g("f-ups")),
        cert_id: num(g("f-cert"), 0), comment: g("f-comment"), mode: g("f-mode"), paranoia: num(g("f-pl"), 1),
        anomaly_threshold: num(g("f-thr"), 5), disabled_rules: nums(g("f-dis")),
        rate_limit: { requests: num(g("f-rl"), 0), window_sec: num(g("f-rlw"), 60), block_sec: num(g("f-rlb"), 60) },
        ip_allow: lines(g("f-allow")), ip_deny: lines(g("f-deny")),
        bot_challenge: { enabled: $("f-bot").checked, difficulty: num(g("f-botd"), 16), ttl_sec: num(g("f-bott"), 3600), exclude_paths: lines(g("f-botx")) },
        auth: { enabled: $("f-auth").checked, password_hash: au.password_hash || "", ttl_sec: num(g("f-autht"), 28800), exclude_paths: lines(g("f-authx")) },
        upstream_host: g("f-uh").trim(), redirect_https: $("f-redir").checked, upstream_insecure: $("f-uins").checked
      };
      if (g("f-authp")) body.auth.password = g("f-authp");
      if (body.rate_limit.requests === 0) body.rate_limit = { requests: 0, window_sec: 0, block_sec: 0 };
      api(isNew ? "POST" : "PUT", "/api/open/site", body).then(function (saved) {
        toast(isNew ? "Đã tạo ứng dụng" : "Đã lưu"); location.hash = "#/sites/" + saved.id; if (!isNew) route();
      }).catch(function (e) { toast(e.message, true); });
    });
    v.appendChild(form);
  }

  // ---------- events ----------
  function eventsView(v) {
    v.appendChild(el("h1", { text: "Sự kiện tấn công" }));
    var bar = el("div", { class: "row" });
    var list = el("div");
    var detail = el("div");
    v.appendChild(bar); v.appendChild(el("div", { class: "spacer" })); v.appendChild(detail); v.appendChild(list);
    loadAll().then(function () {
      var sel = select("ev-site", [[0, "Tất cả ứng dụng"]].concat(state.sites.map(function (s) { return [s.id, s.name]; })), 0);
      sel.addEventListener("change", load);
      bar.appendChild(el("div", {}, [sel])); bar.appendChild(el("button", { class: "btn", text: "Làm mới", onclick: load }));
      load();
    });
    function load() {
      api("GET", "/api/open/events?limit=500&site_id=" + $("ev-site").value).then(function (d) {
        clear(list); clear(detail);
        var tb = el("tbody");
        (d.data || []).forEach(function (e) {
          var cls = e.action === "monitor" ? "warn" : e.kind === "waf" ? "bad" : "info";
          tb.appendChild(el("tr", { class: "click", onclick: function () { showEvent(detail, e); } }, [
            el("td", { text: fmtTime(e.time) }), el("td", { text: siteName(e.site_id) }), el("td", { class: "mono", text: e.client_ip }),
            el("td", { class: "mono", text: e.method + " " + e.uri.slice(0, 120) }),
            el("td", {}, [el("span", { class: "pill " + cls, text: e.kind + (e.action === "monitor" ? " (giám sát)" : "") })]),
            el("td", { text: (e.tags || []).join(", ") })]));
        });
        if (!(d.data || []).length) tb.appendChild(el("tr", {}, [el("td", { colspan: "6", class: "muted", text: "Chưa có sự kiện." })]));
        list.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, ["Thời gian", "Ứng dụng", "IP", "Request", "Loại", "Phân loại"].map(function (h) { return el("th", { text: h }); }))]), tb])]));
      }).catch(function (e) { toast(e.message, true); });
    }
  }

  function showEvent(box, e) {
    clear(box);
    var site = state.sites.filter(function (s) { return s.id === e.site_id; })[0];
    var rules = el("tbody");
    (e.rules || []).forEach(function (r) {
      rules.appendChild(el("tr", {}, [el("td", { class: "mono nowrap", text: String(r.id) }), el("td", { text: r.msg }), el("td", { class: "mono", text: r.data || "" }), el("td", { text: r.severity && r.severity !== "unknown" ? r.severity : "" })]));
    });
    var actions = el("div", { class: "row" });
    if (site) {
      actions.appendChild(el("button", { class: "btn danger small", text: "Chặn IP " + e.client_ip, onclick: function () {
        var s = JSON.parse(JSON.stringify(site)); s.ip_deny = (s.ip_deny || []).concat([e.client_ip]);
        api("PUT", "/api/open/site", s).then(function () { toast("Đã thêm " + e.client_ip + " vào denylist của " + site.name); loadAll(); }).catch(function (x) { toast(x.message, true); });
      } }));
      var fp = (e.rules || []).map(function (r) { return r.id; }).filter(function (id) { return id < 949000; });
      if (fp.length) actions.appendChild(el("button", { class: "btn small", text: "Báo chặn nhầm (tắt " + fp.length + " rule)", onclick: function () {
        if (!confirm("Tắt các rule " + fp.join(", ") + " cho " + site.name + "?")) return;
        var s = JSON.parse(JSON.stringify(site)); s.disabled_rules = Array.from(new Set((s.disabled_rules || []).concat(fp)));
        api("PUT", "/api/open/site", s).then(function () { toast("Đã tắt rule cho " + site.name); loadAll(); }).catch(function (x) { toast(x.message, true); });
      } }));
    }
    box.appendChild(el("div", { class: "card" }, [
      el("div", { class: "row" }, [el("b", { text: "Sự kiện " + e.id }), el("span", { class: "spacer" }), el("button", { class: "btn ghost small", text: "Đóng", onclick: function () { clear(box); } })]),
      el("p", { class: "mono detail", text: e.method + " " + e.host + e.uri + "\nIP: " + e.client_ip + "\nUser-Agent: " + (e.user_agent || "") + "\nHTTP " + e.status + " · " + fmtTime(e.time) }),
      (e.rules || []).length ? el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, ["Rule", "Mô tả", "Dữ liệu khớp", "Mức độ"].map(function (h) { return el("th", { text: h }); }))]), rules])]) : null,
      el("div", { class: "spacer" }), actions
    ]));
    box.appendChild(el("div", { class: "spacer" }));
    window.scrollTo(0, 0);
  }

  // ---------- certificates ----------
  function certs(v) {
    v.appendChild(el("h1", { text: "Chứng chỉ TLS" }));
    var list = el("div");
    v.appendChild(list);
    function readFile(target) {
      return el("input", { type: "file", accept: ".pem,.crt,.key,.cer", onchange: function (ev) {
        var f = ev.target.files[0]; if (!f) return;
        var rd = new FileReader(); rd.onload = function () { $(target).value = rd.result; }; rd.readAsText(f);
      } });
    }
    var form = el("form", {}, [el("fieldset", {}, [el("legend", { text: "Thêm chứng chỉ" }), el("div", { class: "grid2" }, [
      field("Certificate (PEM, kèm chain)", el("textarea", { id: "c-crt" })), field("Private key (PEM)", el("textarea", { id: "c-key" }))]),
      el("div", { class: "row" }, [readFile("c-crt"), readFile("c-key")]), el("div", { class: "spacer" }),
      el("button", { type: "submit", class: "btn primary", text: "Tải lên" })])]);
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      api("POST", "/api/open/cert", { crt: $("c-crt").value, key: $("c-key").value }).then(function () { toast("Đã thêm chứng chỉ"); route(); }).catch(function (x) { toast(x.message, true); });
    });
    loadAll().then(function () {
      var tb = el("tbody"), now = Date.now();
      state.certs.forEach(function (c) {
        var days = Math.floor((new Date(c.not_after) - now) / 86400000);
        var used = state.sites.filter(function (s) { return s.cert_id === c.id; }).map(function (s) { return s.name; });
        tb.appendChild(el("tr", {}, [
          el("td", { class: "mono", text: c.domains.join(", ") }), el("td", { text: c.issuer || "" }),
          el("td", {}, [el("span", { class: "pill " + (days < 0 ? "bad" : days < 30 ? "warn" : "ok"), text: days < 0 ? "Đã hết hạn" : "Còn " + days + " ngày" })]),
          el("td", { text: used.join(", ") || "–" }),
          el("td", {}, [el("button", { class: "btn danger small", text: "Xoá", onclick: function () {
            if (!confirm("Xoá chứng chỉ " + c.domains.join(", ") + "?")) return;
            api("DELETE", "/api/open/cert", { ids: [c.id] }).then(function () { toast("Đã xoá"); route(); }).catch(function (x) { toast(x.message, true); });
          } })])]));
      });
      if (!state.certs.length) tb.appendChild(el("tr", {}, [el("td", { colspan: "5", class: "muted", text: "Chưa có chứng chỉ." })]));
      list.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, ["Tên miền", "Cấp bởi", "Hiệu lực", "Dùng cho", ""].map(function (h) { return el("th", { text: h }); }))]), tb])]));
      list.appendChild(form);
    }).catch(function (e) { toast(e.message, true); });
  }

  show();
})();
