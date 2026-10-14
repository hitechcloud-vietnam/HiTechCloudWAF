/* HiTechCloud WAF console. All dynamic text is inserted with textContent. */
(function () {
  "use strict";
  var KEY = "hcw-waf-token", SKEY = "hcw-waf-session", LKEY = "hcw-waf-lang";
  var state = { sites: [], certs: [], me: null };

  // ---------- i18n (dictionaries live in i18n.js) ----------
  var I18N = window.HCWI18n || { base: "vi", langs: [{ code: "vi", label: "VI", name: "Tiếng Việt", locale: "vi-VN" }], dict: {}, missing: {} };
  var lang = I18N.base;
  function hasOwn(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function langInfo(code) {
    for (var i = 0; i < I18N.langs.length; i++) if (I18N.langs[i].code === code) return I18N.langs[i];
    return null;
  }
  function lookup(key) {
    var d = I18N.dict[lang];
    if (!d) return key;
    if (hasOwn(d, key)) return d[key];
    I18N.missing[key] = true;
    return key;
  }
  function fill(s, args, from) {
    return s.replace(/\{(\d+)\}/g, function (m, i) { var v = args[from + Number(i)]; return v === undefined ? m : String(v); });
  }
  // t("Vietnamese text {0}", arg0, ...) returns the text in the current language.
  function t(s) { return fill(lookup(s), arguments, 1); }
  // tc(context, text, ...) is t() with a disambiguating "context|text" key.
  function tc(ctx, s) {
    var d = I18N.dict[lang], k = ctx + "|" + s;
    return fill(d && hasOwn(d, k) ? d[k] : lookup(s), arguments, 2);
  }
  function locale() { var l = langInfo(lang); return (l && l.locale) || "vi-VN"; }
  function th(h) { return el("th", { text: h }); }

  // ---------- helpers ----------
  function $(id) { return document.getElementById(id); }
  function stored(k) { try { return sessionStorage.getItem(k) || ""; } catch (e) { return ""; } }
  function store(k, v) { try { if (v) sessionStorage.setItem(k, v); else sessionStorage.removeItem(k); } catch (e) {} }
  function token() { return stored(KEY); }
  function session() { return stored(SKEY); }
  function setToken(t) { store(KEY, t); }
  function signedIn() { return !!(token() || session()); }
  function signOut() { store(KEY, ""); store(SKEY, ""); state.me = null; }

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
  function fmtTime(s) { var d = new Date(s); return isNaN(d) ? "" : d.toLocaleString(locale()); }
  function lines(s) { return (s || "").split(/[\n,]+/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function nums(s) { return lines(s).map(Number).filter(function (x) { return x > 0; }); }
  function num(v, d) { var n = parseInt(v, 10); return isNaN(n) ? d : n; }

  function api(method, path, body) {
    return fetch(path, {
      method: method,
      headers: session() ? { "X-HCW-Session": session(), "Content-Type": "application/json" } : { "X-HCW-API-TOKEN": token(), "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return { err: "http_" + r.status, msg: r.statusText }; }).then(function (j) {
        if (r.status === 401 && path !== "/api/auth/login") { signOut(); show(); }
        if (!r.ok || j.err) throw new Error(j.msg || j.err || ("HTTP " + r.status));
        return j.data;
      });
    });
  }

  // ---------- shell ----------
  function show() {
    var authed = signedIn();
    $("login").hidden = authed; $("app").hidden = !authed;
    if (!authed) return;
    api("GET", "/api/open/me").then(function (me) {
      state.me = me;
      document.body.classList.toggle("viewer", me.role !== "admin");
      renderWho();
      route();
    }).catch(function () {});
  }
  function renderWho() {
    var me = state.me;
    $("who").textContent = !me ? "" : me.account ? me.username + " (" + (me.role === "admin" ? t("quản trị") : t("chỉ xem")) + ")" : t("API token");
  }
  var tokenMode = false;
  function renderLoginMode() {
    $("login-mode").textContent = tokenMode ? t("Đăng nhập bằng tài khoản") : t("Dùng API token");
  }
  $("login-mode").addEventListener("click", function (e) {
    e.preventDefault(); tokenMode = !tokenMode;
    $("login-user").hidden = tokenMode; $("login-token").hidden = !tokenMode;
    renderLoginMode();
  });

  // ---------- language ----------
  function savedLang() { try { return localStorage.getItem(LKEY) || ""; } catch (e) { return ""; } }
  function saveLang(code) { try { localStorage.setItem(LKEY, code); } catch (e) {} }
  // applyLang translates the static page and redraws whatever depends on the language.
  function applyLang(code, rerender) {
    lang = langInfo(code) ? code : I18N.base;
    document.documentElement.lang = lang;
    Array.prototype.forEach.call(document.querySelectorAll("[data-i18n]"), function (n) { n.textContent = t(n.getAttribute("data-i18n")); });
    Array.prototype.forEach.call(document.querySelectorAll("[data-i18n-placeholder]"), function (n) { n.placeholder = t(n.getAttribute("data-i18n-placeholder")); });
    Array.prototype.forEach.call(document.querySelectorAll(".lang-switch"), function (box) {
      clear(box);
      box.setAttribute("role", "group"); box.setAttribute("aria-label", t("Ngôn ngữ"));
      I18N.langs.forEach(function (l) {
        box.appendChild(el("button", { type: "button", class: l.code === lang ? "active" : "", lang: l.code, title: l.name,
          "aria-pressed": l.code === lang ? "true" : "false", text: l.label,
          onclick: function () { if (l.code !== lang) { saveLang(l.code); applyLang(l.code, true); } } }));
      });
    });
    renderLoginMode();
    renderWho();
    if (rerender) {
      $("login-err").textContent = ""; $("toast").hidden = true; // both still hold the old language
      if (signedIn() && state.me) route();
    }
  }
  applyLang(savedLang(), false);
  $("login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    $("login-err").textContent = "";
    if (tokenMode) {
      setToken($("token").value.trim());
      api("GET", "/api/open/info").then(function () { $("token").value = ""; show(); })
        .catch(function (err) { signOut(); $("login-err").textContent = t("Token không hợp lệ: {0}", err.message); });
      return;
    }
    fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("username").value.trim(), password: $("password").value, otp: $("otp").value.trim() }) })
      .then(function (r) { return r.json(); }).then(function (j) {
        if (j.err === "otp_required") { $("otp").hidden = false; $("otp").focus(); $("login-err").textContent = t("Nhập mã từ ứng dụng xác thực."); return; }
        if (j.err) { $("login-err").textContent = j.msg || j.err; return; }
        store(SKEY, j.data.token); $("password").value = ""; $("otp").value = ""; $("otp").hidden = true; show();
      }).catch(function (err) { $("login-err").textContent = err.message; });
  });
  $("logout").addEventListener("click", function () {
    var done = function () { signOut(); show(); };
    if (session()) api("POST", "/api/auth/logout").then(done, done); else done();
  });

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
    var views = { dashboard: dashboard, sites: sites, events: eventsView, certs: certs, users: usersView, account: accountView, system: systemView };
    (views[parts[0]] || dashboard)(v, parts.slice(1));
  }
  window.addEventListener("hashchange", function () { if (signedIn()) route(); });

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
    v.appendChild(el("div", { class: "row" }, [el("h1", { text: t("Tổng quan") }), el("span", { class: "spacer" }),
      el("button", { class: "btn admin-only", text: t("Gửi thử cảnh báo"), onclick: function () {
        api("POST", "/api/open/alerts/test").then(function () { toast(t("Đã gửi tin nhắn thử tới Telegram/webhook")); }).catch(function (e) { toast(e.message, true); });
      } })]));
    var cards = el("div", { class: "cards" });
    var chartCard = el("div", { class: "card" });
    var tableWrap = el("div");
    v.appendChild(cards); v.appendChild(chartCard); v.appendChild(tableWrap);
    Promise.all([loadAll(), api("GET", "/api/open/timeseries"), api("GET", "/api/open/stats"), api("GET", "/api/open/info"), api("GET", "/api/open/events?limit=200")])
      .then(function (r) {
        var series = r[1], stats = r[2] || {}, info = r[3], recent = (r[4].data || []);
        $("ver").textContent = "v" + info.version;
        var sum = function (k) { return series.reduce(function (a, b) { return a + (b[k] || 0); }, 0); };
        [[t("Ứng dụng"), state.sites.length], [t("Request (60 phút)"), sum("requests")], [t("Bị chặn (60 phút)"), sum("blocked")],
         [t("Rate limit"), sum("rate_limited")], [t("ACL IP"), sum("acl_blocked")], [t("Bot bị loại"), sum("bot_failed")]]
          .forEach(function (c) { cards.appendChild(el("div", { class: "card stat" }, [el("span", { class: "muted", text: c[0] }), el("b", { text: String(c[1]) })])); });

        chartCard.appendChild(el("div", { class: "row" }, [el("b", { text: t("Lưu lượng 60 phút gần nhất") }), el("span", { class: "spacer" }),
          el("span", { class: "legend" }, [el("span", {}, [el("i", { class: "lg-req" }), t("Request")]), el("span", {}, [el("i", { class: "lg-blk" }), t("Bị chặn")])])]));
        chartCard.appendChild(chart(series));

        // Top attack types from recent events
        var tags = {};
        recent.forEach(function (e) { (e.tags || []).forEach(function (t) { tags[t] = (tags[t] || 0) + 1; }); if (e.kind !== "waf") tags[e.kind] = (tags[e.kind] || 0) + 1; });
        var top = Object.keys(tags).sort(function (a, b) { return tags[b] - tags[a]; }).slice(0, 8);
        tableWrap.appendChild(el("h2", { text: t("Loại tấn công gần đây") }));
        tableWrap.appendChild(top.length ? el("div", { class: "row" }, top.map(function (tag) { return el("span", { class: "pill bad", text: tag + " · " + tags[tag] }); }))
          : el("p", { class: "muted", text: t("Chưa có sự kiện.") }));

        tableWrap.appendChild(el("h2", { text: t("Theo ứng dụng (từ khi khởi động)") }));
        var tb = el("tbody");
        state.sites.forEach(function (s) {
          var c = stats[s.id] || {};
          tb.appendChild(el("tr", { class: "click", onclick: function () { location.hash = "#/sites/" + s.id; } }, [
            el("td", { text: s.name }), el("td", {}, [modePill(s.mode)]),
            el("td", { text: String(c.requests || 0) }), el("td", { text: String(c.blocked || 0) }),
            el("td", { text: String(c.monitored || 0) }), el("td", { text: String((c.rate_limited || 0) + (c.acl_blocked || 0) + (c.bot_failed || 0)) })]));
        });
        tableWrap.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [tc("col", "Ứng dụng"), t("Chế độ"), t("Request"), tc("col", "Chặn"), t("Monitor"), t("Rate/ACL/Bot")].map(th))]), tb])]));
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
        var tt = document.createElementNS(SVG, "title");
        tt.textContent = t("{0} – request {1}, chặn {2}", new Date(b.minute * 1000).toLocaleTimeString(locale()), b.requests, blocked);
        r.appendChild(tt); svg.appendChild(r);
      });
    });
    return svg;
  }
  function modePill(m) { return el("span", { class: "pill " + (m === "block" ? "ok" : m === "monitor" ? "warn" : ""), text: m === "block" ? t("Chặn") : m === "monitor" ? t("Giám sát") : t("Tắt") }); }

  // ---------- sites ----------
  function sites(v, args) {
    Promise.all([loadAll(), api("GET", "/api/open/upstreams").catch(function () { return {}; })]).then(function (r) {
      var health = r[1] || {};
      if (args[0] === "new") return siteForm(v, null);
      if (args[0]) {
        var s = state.sites.filter(function (x) { return String(x.id) === args[0]; })[0];
        return s ? siteForm(v, s) : (v.appendChild(el("p", { text: t("Không tìm thấy ứng dụng.") })));
      }
      v.appendChild(el("div", { class: "row" }, [el("h1", { text: t("Ứng dụng được bảo vệ") }), el("span", { class: "spacer" }),
        el("a", { class: "btn primary admin-only", href: "#/sites/new", text: t("+ Thêm ứng dụng") })]));
      var tb = el("tbody");
      state.sites.forEach(function (s) {
        var feats = [];
        if (s.rate_limit && s.rate_limit.requests) feats.push(t("rate {0}/{1}s", s.rate_limit.requests, s.rate_limit.window_sec));
        if (s.bot_challenge && s.bot_challenge.enabled) feats.push(t("anti-bot"));
        if (s.auth && s.auth.enabled) feats.push(t("mật khẩu"));
        if ((s.ip_allow || []).length) feats.push(t("allowlist"));
        if ((s.ip_deny || []).length) feats.push(t("deny {0}", s.ip_deny.length));
        if ((s.country_allow || []).length || (s.country_deny || []).length) feats.push(t("geo"));
        if (s.dynamic_protection && (s.dynamic_protection.html || s.dynamic_protection.js)) feats.push(t("bảo vệ động"));
        if ((s.rules || []).length) feats.push(s.rules.length === 1 ? t("1 rule") : t("{0} rule", s.rules.length));
        tb.appendChild(el("tr", { class: "click", onclick: function () { location.hash = "#/sites/" + s.id; } }, [
          el("td", {}, [el("b", { text: s.name }), el("div", { class: "muted mono", text: s.server_names.join(", ") })]),
          el("td", { class: "mono", text: s.ports.join(", ") }),
          el("td", {}, (health[s.id] || s.upstreams.map(function (u) { return { url: u, healthy: true }; })).map(function (u) {
            return el("div", { class: "mono", title: u.last_error || "" }, [el("span", { class: u.healthy ? "dot ok" : "dot bad" }), u.url]);
          })),
          el("td", {}, [modePill(s.mode)]),
          el("td", { text: "PL" + s.paranoia }),
          el("td", { text: feats.join(", ") || "–" })]));
      });
      if (!state.sites.length) tb.appendChild(el("tr", {}, [el("td", { colspan: "6", class: "muted", text: t("Chưa có ứng dụng nào. Bấm “Thêm ứng dụng”.") })]));
      v.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [tc("col", "Ứng dụng"), t("Cổng"), t("Upstream"), t("Chế độ"), t("Paranoia"), t("Tính năng")].map(th))]), tb])]));
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
    v.appendChild(el("div", { class: "row" }, [el("h1", { text: isNew ? t("Thêm ứng dụng") : t("Ứng dụng: {0}", s.name) }), el("span", { class: "spacer" }),
      el("a", { class: "btn", href: "#/sites", text: t("← Danh sách") })]));
    var certOpts = [[0, t("— Không dùng HTTPS —")]].concat(state.certs.map(function (c) { return [c.id, t("{0} (hết hạn {1})", c.domains.join(", "), fmtTime(c.not_after))]; }));
    var form = el("form", {}, [
      el("fieldset", {}, [el("legend", { text: t("Cơ bản") }), el("div", { class: "grid2" }, [
        field(t("Tên hiển thị"), el("input", { id: "f-name", value: s.name || "" })),
        field(t("Tên miền"), el("textarea", { id: "f-names", value: (s.server_names || []).join("\n") }), t("Mỗi dòng một tên miền. Hỗ trợ *.example.com; “_” = mọi tên miền.")),
        field(t("Cổng"), el("input", { id: "f-ports", value: (s.ports || []).join(", ") }), t("Ví dụ: 80, 443_ssl (cổng _ssl cần chứng chỉ).")),
        field(t("Upstream (server gốc)"), el("textarea", { id: "f-ups", value: (s.upstreams || []).join("\n") }), t("http(s)://ip:port – nhiều dòng = cân bằng tải, tự loại upstream lỗi.")),
        field(t("Chứng chỉ HTTPS"), select("f-cert", certOpts, s.cert_id || 0)),
        el("div", {}, [check(t("Tự động cấp chứng chỉ Let's Encrypt"), "f-auto", s.auto_tls), check(t("Bật HSTS"), "f-hsts", s.hsts),
          el("div", { class: "hint", text: t("Let's Encrypt cần tên miền trỏ về node, cổng 80 mở và acme.enabled trong cấu hình.") })]),
        field(t("Ghi chú"), el("input", { id: "f-comment", value: s.comment || "" }))])]),
      el("fieldset", {}, [el("legend", { text: t("Phát hiện tấn công (OWASP CRS)") }), el("div", { class: "grid2" }, [
        field(t("Chế độ"), select("f-mode", [["block", t("Chặn")], ["monitor", t("Giám sát (chỉ ghi log)")], ["off", t("Tắt (proxy thuần)")]], s.mode)),
        field(t("Mức paranoia"), select("f-pl", [[1, t("1 – Cân bằng (khuyên dùng)")], [2, t("2 – Chặt hơn")], [3, t("3 – Nghiêm ngặt")], [4, t("4 – Rất nghiêm ngặt")]], s.paranoia), t("Mức 3–4 dễ chặn nhầm, cần tinh chỉnh.")),
        field(t("Ngưỡng điểm bất thường"), el("input", { id: "f-thr", type: "number", min: "1", value: s.anomaly_threshold || 5 })),
        field(t("Tắt rule (ID)"), el("input", { id: "f-dis", value: (s.disabled_rules || []).join(", ") }), t("Dùng khi bị chặn nhầm; ID lấy từ trang Sự kiện."))]),
        field(t("Rule tuỳ chỉnh (SecLang)"), el("textarea", { id: "f-rules", value: s.custom_rules || "", placeholder: "SecRule ARGS:debug \"@streq 1\" \"id:1001,phase:1,deny,status:403,log,msg:'debug blocked'\"" }), t("ID rule 1–99999. Không cho phép Include hay đọc file."))]),
      el("fieldset", {}, [el("legend", { text: t("Giới hạn & kiểm soát truy cập") }), el("div", { class: "grid2" }, [
        field(t("Rate limit: số request"), el("input", { id: "f-rl", type: "number", min: "0", value: rl.requests || 0 }), t("0 = tắt.")),
        field(t("Trong (giây)"), el("input", { id: "f-rlw", type: "number", min: "0", value: rl.window_sec || 60 })),
        field(t("Chặn trong (giây)"), el("input", { id: "f-rlb", type: "number", min: "0", value: rl.block_sec || 60 })),
        field(t("IP cho phép (allowlist)"), el("textarea", { id: "f-allow", value: (s.ip_allow || []).join("\n") }), t("Nếu có, chỉ các IP/CIDR này được truy cập.")),
        field(t("IP chặn (denylist)"), el("textarea", { id: "f-deny", value: (s.ip_deny || []).join("\n") })),
        field(t("Chỉ cho phép quốc gia"), el("input", { id: "f-ca", value: (s.country_allow || []).join(", "), placeholder: "VN" }), t("Mã ISO 2 ký tự, cách nhau dấu phẩy. Cần geoip_db trên node.")),
        field(t("Chặn quốc gia"), el("input", { id: "f-cd", value: (s.country_deny || []).join(", "), placeholder: "RU, KP" }))])]),
      el("fieldset", {}, [el("legend", { text: t("Anti-bot & mật khẩu") }), el("div", { class: "grid2" }, [
        el("div", {}, [check(t("Bật anti-bot challenge (JS proof-of-work)"), "f-bot", bot.enabled),
          field(t("Độ khó"), el("input", { id: "f-botd", type: "number", min: "8", max: "24", value: bot.difficulty || 16 }), t("16 ≈ dưới 1 giây; +1 gấp đôi thời gian.")),
          field(t("Hiệu lực (giây)"), el("input", { id: "f-bott", type: "number", value: bot.ttl_sec || 3600 })),
          field(t("Bỏ qua đường dẫn"), el("textarea", { id: "f-botx", value: (bot.exclude_paths || []).join("\n") }), t("Ví dụ /api/ cho app mobile, webhook."))]),
        el("div", {}, [check(t("Bật bảo vệ bằng mật khẩu"), "f-auth", au.enabled),
          field(au.password_hash ? t("Mật khẩu mới (để trống = giữ nguyên)") : t("Mật khẩu"), el("input", { id: "f-authp", type: "password", autocomplete: "new-password" }), t("8–72 ký tự, lưu dạng bcrypt.")),
          field(t("Hiệu lực (giây)"), el("input", { id: "f-autht", type: "number", value: au.ttl_sec || 28800 })),
          field(t("Bỏ qua đường dẫn"), el("textarea", { id: "f-authx", value: (au.exclude_paths || []).join("\n") }))])])]),
      rulesFieldset(s.rules || []),
      el("fieldset", {}, [el("legend", { text: t("Bảo vệ động (chống thu thập dữ liệu)") }), el("div", { class: "grid2" }, [
        el("div", {}, [check(t("Mã hoá HTML mỗi lần tải trang"), "f-dhtml", (s.dynamic_protection || {}).html),
          check(t("Mã hoá file JavaScript"), "f-djs", (s.dynamic_protection || {}).js),
          el("div", { class: "hint", text: t("Nội dung thay đổi mỗi request; bot không chạy JS chỉ thấy dữ liệu vô nghĩa. Trang có CSP riêng, ES module và file > 4 MB được giữ nguyên. Ảnh hưởng SEO: chỉ bật cho khu vực cần bảo vệ.") })]),
        field(t("Chỉ áp dụng cho đường dẫn"), el("textarea", { id: "f-dpaths", value: ((s.dynamic_protection || {}).paths || []).join("\n") }), t("Để trống = toàn site. Ví dụ /san-pham/"))])]),
      trafficFieldset(s),
      el("fieldset", {}, [el("legend", { text: t("Kiểm tra sức khỏe upstream") }), el("div", { class: "grid2" }, [
        field(t("Đường dẫn kiểm tra"), el("input", { id: "f-hcp", value: (s.health_check || {}).path || "", placeholder: "/healthz" }), t("Để trống = tắt. Upstream trả lỗi/≥400 nhiều lần liên tiếp sẽ bị loại khỏi vòng chia tải.")),
        field(t("Chu kỳ (giây)"), el("input", { id: "f-hci", type: "number", min: "1", value: (s.health_check || {}).interval_sec || 10 })),
        field(t("Số lần lỗi để loại"), el("input", { id: "f-hcu", type: "number", min: "1", value: (s.health_check || {}).unhealthy || 3 })),
        field(t("Số lần tốt để đưa lại"), el("input", { id: "f-hch", type: "number", min: "1", value: (s.health_check || {}).healthy || 2 }))])]),
      el("fieldset", {}, [el("legend", { text: t("Proxy nâng cao") }), el("div", { class: "grid2" }, [
        field(t("Host gửi lên upstream"), el("input", { id: "f-uh", value: s.upstream_host || "" }), t("Để trống = giữ Host của khách.")),
        el("div", {}, [check(t("Chuyển hướng HTTP → HTTPS"), "f-redir", s.redirect_https), check(t("Bỏ qua kiểm tra chứng chỉ upstream"), "f-uins", s.upstream_insecure)])])]),
      el("div", { class: "row" }, [el("button", { type: "submit", class: "btn primary admin-only", text: isNew ? t("Tạo ứng dụng") : t("Lưu thay đổi") }),
        isNew ? null : el("button", { type: "button", class: "btn danger admin-only", text: t("Xoá ứng dụng"), onclick: function () {
          if (!confirm(t("Xoá ứng dụng {0}?", s.name))) return;
          api("DELETE", "/api/open/site", { ids: [s.id] }).then(function () { toast(t("Đã xoá")); location.hash = "#/sites"; }).catch(function (e) { toast(e.message, true); });
        } }),
        isNew || !(s.cache || {}).enabled ? null : el("button", { type: "button", class: "btn admin-only", text: t("Xoá cache"), onclick: function () {
          if (!confirm(t("Xoá toàn bộ cache của {0}?", s.name))) return;
          api("POST", "/api/open/cache/purge", { site_id: s.id, prefix: "" }).then(function (d) { toast(t("Đã xoá {0} object khỏi cache", d.removed)); }).catch(function (e) { toast(e.message, true); });
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
        country_allow: lines(g("f-ca").toUpperCase()), country_deny: lines(g("f-cd").toUpperCase()),
        bot_challenge: { enabled: $("f-bot").checked, difficulty: num(g("f-botd"), 16), ttl_sec: num(g("f-bott"), 3600), exclude_paths: lines(g("f-botx")) },
        auth: { enabled: $("f-auth").checked, password_hash: au.password_hash || "", ttl_sec: num(g("f-autht"), 28800), exclude_paths: lines(g("f-authx")) },
        upstream_host: g("f-uh").trim(), redirect_https: $("f-redir").checked, upstream_insecure: $("f-uins").checked,
        dynamic_protection: { html: $("f-dhtml").checked, js: $("f-djs").checked, paths: lines(g("f-dpaths")) },
        rules: collectRules(),
        health_check: g("f-hcp").trim() ? { path: g("f-hcp").trim(), interval_sec: num(g("f-hci"), 10), unhealthy: num(g("f-hcu"), 3), healthy: num(g("f-hch"), 2) } : { path: "" },
        auto_tls: $("f-auto").checked, hsts: $("f-hsts").checked, custom_rules: g("f-rules")
      };
      if (g("f-authp")) body.auth.password = g("f-authp");
      if (!collectTraffic(body)) return;
      if (body.rate_limit.requests === 0) body.rate_limit = { requests: 0, window_sec: 0, block_sec: 0 };
      api(isNew ? "POST" : "PUT", "/api/open/site", body).then(function (saved) {
        toast(isNew ? t("Đã tạo ứng dụng") : t("Đã lưu")); location.hash = "#/sites/" + saved.id; if (!isNew) route();
      }).catch(function (e) { toast(e.message, true); });
    });
    v.appendChild(form);
  }

  // ---------- path rules editor ----------
  function actions() { return [["allow", t("Cho phép (whitelist)")], ["deny", tc("action", "Chặn")], ["skip_waf", t("Bỏ qua WAF")], ["rate_limit", t("Giới hạn tốc độ")]]; }
  function ruleRow(r) {
    r = r || { action: "rate_limit", rate_limit: {} };
    var rl = r.rate_limit || {};
    var act = select("", actions(), r.action); act.removeAttribute("id"); act.className = "r-act";
    var tr = el("tr", {}, [
      el("td", {}, [el("input", { class: "r-path", value: r.path || "/", placeholder: "/login" })]),
      el("td", {}, [el("input", { class: "r-exact", type: "checkbox", checked: r.exact })]),
      el("td", {}, [el("input", { class: "r-methods", value: (r.methods || []).join(","), placeholder: "POST" })]),
      el("td", {}, [el("input", { class: "r-ips", value: (r.ips || []).join(","), placeholder: t("mọi IP") })]),
      el("td", {}, [act]),
      el("td", {}, [el("input", { class: "r-req", type: "number", min: "0", value: rl.requests || "", placeholder: "5" })]),
      el("td", {}, [el("input", { class: "r-win", type: "number", min: "0", value: rl.window_sec || "", placeholder: "60" })]),
      el("td", {}, [el("input", { class: "r-blk", type: "number", min: "0", value: rl.block_sec || "", placeholder: "300" })]),
      el("td", {}, [el("button", { type: "button", class: "btn ghost small", text: "✕", title: t("Xoá rule"), "aria-label": t("Xoá rule"), onclick: function () { tr.parentNode.removeChild(tr); } })])
    ]);
    return tr;
  }
  function rulesFieldset(rules) {
    var tb = el("tbody", { id: "rules-body" });
    rules.forEach(function (r) { tb.appendChild(ruleRow(r)); });
    return el("fieldset", {}, [el("legend", { text: t("Rule theo đường dẫn") }),
      el("div", { class: "hint", text: t("Xét theo thứ tự; Cho phép/Chặn dừng việc xét. Ví dụ: giới hạn POST /login 5 lần/60s; cho phép /webhook từ IP đối tác; bỏ qua WAF cho /api/upload.") }),
      el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [t("Đường dẫn"), t("Chính xác"), t("Method"), t("IP nguồn"), t("Hành động"), t("Request"), t("Trong (s)"), t("Chặn (s)"), ""].map(th))]), tb])]),
      el("div", { class: "spacer" }),
      el("button", { type: "button", class: "btn small", text: t("+ Thêm rule"), onclick: function () { tb.appendChild(ruleRow()); } })]);
  }
  function collectRules() {
    var out = [];
    Array.prototype.forEach.call(document.querySelectorAll("#rules-body tr"), function (tr) {
      var q = function (c) { return tr.querySelector("." + c); };
      var r = { path: q("r-path").value.trim(), exact: q("r-exact").checked, methods: lines(q("r-methods").value.toUpperCase()), ips: lines(q("r-ips").value), action: q("r-act").value };
      if (r.action === "rate_limit") r.rate_limit = { requests: num(q("r-req").value, 0), window_sec: num(q("r-win").value, 60), block_sec: num(q("r-blk").value, 300) };
      if (r.path) out.push(r);
    });
    return out;
  }

  // ---------- load balancing & header rewriting ----------
  function lbOptions() { return [["", t("Tự động (round-robin; theo trọng số nếu có weight)")], ["round_robin", t("Round-robin (lần lượt)")], ["weighted", t("Theo trọng số (weight)")], ["least_conn", t("Ít kết nối nhất")], ["ip_hash", t("Theo IP khách (consistent hash)")], ["random", t("Ngẫu nhiên (theo trọng số)")]]; }
  function headerLines(rules) {
    return (rules || []).map(function (r) { return r.action + " " + r.name + (r.value ? ": " + r.value : ""); }).join("\n");
  }
  // One rule per line: "set Name: value", "add Name: value", "remove Name".
  function parseHeaderLines(text, what) {
    var out = [];
    (text || "").split("\n").forEach(function (line, i) {
      line = line.trim();
      if (!line) return;
      var m = /^(set|add|remove)\s+([^\s:]+)\s*(?::\s*(.*))?$/i.exec(line);
      if (!m) throw new Error(t("{0}, dòng {1}: dùng “set Tên: giá trị”, “add Tên: giá trị” hoặc “remove Tên”", what, i + 1));
      out.push({ action: m[1].toLowerCase(), name: m[2], value: (m[3] || "").trim() });
    });
    return out;
  }
  function trafficFieldset(s) {
    var c = s.cache || {};
    return el("div", {}, [el("fieldset", {}, [el("legend", { text: t("Cân bằng tải & header") }), el("div", { class: "grid2" }, [
      field(t("Thuật toán cân bằng tải"), select("f-lb", lbOptions(), s.lb || ""), t("Trọng số: thêm “weight=N” (1–100) sau upstream, ví dụ http://10.0.0.1:8080 weight=3. Mọi thuật toán đều bỏ qua upstream lỗi.")),
      el("div", {}, [check(t("Sticky session (giữ khách ở một upstream bằng cookie)"), "f-sticky", s.sticky),
        field(t("Tên cookie"), el("input", { id: "f-stc", value: s.sticky_cookie || "hcw_srv" })),
        field(t("Hiệu lực cookie (giây)"), el("input", { id: "f-stt", type: "number", min: "0", value: s.sticky_ttl_sec || 0 }), t("0 = đến khi đóng trình duyệt. Upstream lỗi thì khách được chuyển sang upstream khác."))]),
      field(t("Header gửi lên upstream"), el("textarea", { id: "f-reqh", value: headerLines(s.request_headers), placeholder: "set X-Env: production\nremove X-Debug" }), t("Mỗi dòng một rule: set/add/remove. Không sửa được Host (dùng “Host gửi lên upstream”), X-Forwarded-* và header hop-by-hop.")),
      el("div", {}, [field(t("Header trả về cho khách"), el("textarea", { id: "f-resh", value: headerLines(s.response_headers), placeholder: "set X-Frame-Options: SAMEORIGIN\nadd Cache-Control: no-store" })),
        check(t("Ẩn header Server, X-Powered-By của upstream"), "f-hide", s.hide_server_headers)])])]),
      el("fieldset", {}, [el("legend", { text: t("Cache & nén") }), el("div", { class: "grid2" }, [
        el("div", {}, [check(t("Cache response tĩnh trong RAM"), "f-cache", c.enabled),
          check(t("Nén gzip cho trình duyệt"), "f-gzip", s.compress),
          el("div", { class: "hint", text: t("Chỉ cache GET 200 không có Set-Cookie/private/no-store. Nên bật cùng gzip. Nút “Xoá cache” ở cuối form.") })]),
        el("div", {}, [field(t("Thời gian cache (giây)"), el("input", { id: "f-cttl", type: "number", min: "1", max: "86400", value: c.ttl_sec || 300 })),
          field(t("Object tối đa (KB)"), el("input", { id: "f-cmax", type: "number", min: "1", value: c.max_object_kb || 1024 }))]),
        field(t("Cache mọi thứ dưới đường dẫn"), el("textarea", { id: "f-cpaths", value: (c.paths || []).join("\n") }), t("Để trống = cache theo phần mở rộng.")),
        field(t("Phần mở rộng được cache"), el("textarea", { id: "f-cext", value: (c.extensions || []).join("\n"), placeholder: ".css\n.js\n.png" }), t("Để trống = mặc định (css, js, ảnh, font)."))])])]);
  }
  function collectTraffic(body) {
    try {
      body.request_headers = parseHeaderLines($("f-reqh").value, t("Header gửi lên upstream"));
      body.response_headers = parseHeaderLines($("f-resh").value, t("Header trả về cho khách"));
    } catch (e) { toast(e.message, true); return false; }
    body.lb = $("f-lb").value;
    body.sticky = $("f-sticky").checked;
    body.sticky_cookie = $("f-stc").value.trim();
    body.sticky_ttl_sec = num($("f-stt").value, 0);
    body.hide_server_headers = $("f-hide").checked;
    body.compress = $("f-gzip").checked;
    body.cache = { enabled: $("f-cache").checked, ttl_sec: num($("f-cttl").value, 300), max_object_kb: num($("f-cmax").value, 1024),
      paths: lines($("f-cpaths").value), extensions: lines($("f-cext").value) };
    return true;
  }

  // ---------- events ----------
  function eventsView(v) {
    v.appendChild(el("h1", { text: t("Sự kiện tấn công") }));
    var bar = el("div", { class: "row" });
    var list = el("div");
    var detail = el("div");
    v.appendChild(bar); v.appendChild(el("div", { class: "spacer" })); v.appendChild(detail); v.appendChild(list);
    loadAll().then(function () {
      var sel = select("ev-site", [[0, t("Tất cả ứng dụng")]].concat(state.sites.map(function (s) { return [s.id, s.name]; })), 0);
      sel.addEventListener("change", load);
      bar.appendChild(el("div", {}, [sel])); bar.appendChild(el("button", { class: "btn", text: t("Làm mới"), onclick: load }));
      load();
    });
    function load() {
      api("GET", "/api/open/events?limit=500&site_id=" + $("ev-site").value).then(function (d) {
        clear(list); clear(detail);
        var tb = el("tbody");
        (d.data || []).forEach(function (e) {
          var cls = e.action === "monitor" ? "warn" : e.kind === "waf" ? "bad" : "info";
          tb.appendChild(el("tr", { class: "click", onclick: function () { showEvent(detail, e); } }, [
            el("td", { text: fmtTime(e.time) }), el("td", { text: siteName(e.site_id) }), el("td", { class: "mono", text: e.client_ip + (e.country ? " · " + e.country : "") }),
            el("td", { class: "mono", text: e.method + " " + e.uri.slice(0, 120) }),
            el("td", {}, [el("span", { class: "pill " + cls, text: e.action === "monitor" ? t("{0} (giám sát)", e.kind) : e.kind })]),
            el("td", { text: (e.tags || []).join(", ") })]));
        });
        if (!(d.data || []).length) tb.appendChild(el("tr", {}, [el("td", { colspan: "6", class: "muted", text: t("Chưa có sự kiện.") })]));
        list.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [t("Thời gian"), tc("col", "Ứng dụng"), t("IP"), tc("event", "Request"), t("Loại"), t("Phân loại")].map(th))]), tb])]));
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
      actions.appendChild(el("button", { class: "btn danger small admin-only", text: t("Chặn IP {0}", e.client_ip), onclick: function () {
        var s = JSON.parse(JSON.stringify(site)); s.ip_deny = (s.ip_deny || []).concat([e.client_ip]);
        api("PUT", "/api/open/site", s).then(function () { toast(t("Đã thêm {0} vào denylist của {1}", e.client_ip, site.name)); loadAll(); }).catch(function (x) { toast(x.message, true); });
      } }));
      var fp = (e.rules || []).map(function (r) { return r.id; }).filter(function (id) { return id < 949000; });
      if (fp.length) actions.appendChild(el("button", { class: "btn small admin-only", text: t("Báo chặn nhầm (tắt {0} rule)", fp.length), onclick: function () {
        if (!confirm(t("Tắt các rule {0} cho {1}?", fp.join(", "), site.name))) return;
        var s = JSON.parse(JSON.stringify(site)); s.disabled_rules = Array.from(new Set((s.disabled_rules || []).concat(fp)));
        api("PUT", "/api/open/site", s).then(function () { toast(t("Đã tắt rule cho {0}", site.name)); loadAll(); }).catch(function (x) { toast(x.message, true); });
      } }));
    }
    box.appendChild(el("div", { class: "card" }, [
      el("div", { class: "row" }, [el("b", { text: t("Sự kiện {0}", e.id) }), el("span", { class: "spacer" }), el("button", { class: "btn ghost small", text: t("Đóng"), onclick: function () { clear(box); } })]),
      el("p", { class: "mono detail", text: e.method + " " + e.host + e.uri + "\nIP: " + e.client_ip + (e.country ? " (" + e.country + ")" : "") + "\nUser-Agent: " + (e.user_agent || "") + "\nHTTP " + e.status + " · " + fmtTime(e.time) }),
      (e.rules || []).length ? el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [t("Rule"), t("Mô tả"), t("Dữ liệu khớp"), t("Mức độ")].map(th))]), rules])]) : null,
      el("div", { class: "spacer" }), actions
    ]));
    box.appendChild(el("div", { class: "spacer" }));
    window.scrollTo(0, 0);
  }

  // ---------- certificates ----------
  function certs(v) {
    v.appendChild(el("h1", { text: t("Chứng chỉ TLS") }));
    var list = el("div");
    v.appendChild(list);
    function readFile(target) {
      return el("input", { type: "file", accept: ".pem,.crt,.key,.cer", onchange: function (ev) {
        var f = ev.target.files[0]; if (!f) return;
        var rd = new FileReader(); rd.onload = function () { $(target).value = rd.result; }; rd.readAsText(f);
      } });
    }
    var form = el("form", { class: "admin-only" }, [el("fieldset", {}, [el("legend", { text: t("Thêm chứng chỉ") }), el("div", { class: "grid2" }, [
      field(t("Certificate (PEM, kèm chain)"), el("textarea", { id: "c-crt" })), field(t("Private key (PEM)"), el("textarea", { id: "c-key" }))]),
      el("div", { class: "row" }, [readFile("c-crt"), readFile("c-key")]), el("div", { class: "spacer" }),
      el("button", { type: "submit", class: "btn primary", text: t("Tải lên") })])]);
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      api("POST", "/api/open/cert", { crt: $("c-crt").value, key: $("c-key").value }).then(function () { toast(t("Đã thêm chứng chỉ")); route(); }).catch(function (x) { toast(x.message, true); });
    });
    loadAll().then(function () {
      var tb = el("tbody"), now = Date.now();
      state.certs.forEach(function (c) {
        var days = Math.floor((new Date(c.not_after) - now) / 86400000);
        var used = state.sites.filter(function (s) { return s.cert_id === c.id; }).map(function (s) { return s.name; });
        tb.appendChild(el("tr", {}, [
          el("td", { class: "mono", text: c.domains.join(", ") }), el("td", { text: c.issuer || "" }),
          el("td", {}, [el("span", { class: "pill " + (days < 0 ? "bad" : days < 30 ? "warn" : "ok"), text: days < 0 ? t("Đã hết hạn") : days === 1 ? t("Còn 1 ngày") : t("Còn {0} ngày", days) })]),
          el("td", { text: used.join(", ") || "–" }),
          el("td", {}, [el("button", { class: "btn danger small admin-only", text: t("Xoá"), onclick: function () {
            if (!confirm(t("Xoá chứng chỉ {0}?", c.domains.join(", ")))) return;
            api("DELETE", "/api/open/cert", { ids: [c.id] }).then(function () { toast(t("Đã xoá")); route(); }).catch(function (x) { toast(x.message, true); });
          } })])]));
      });
      if (!state.certs.length) tb.appendChild(el("tr", {}, [el("td", { colspan: "5", class: "muted", text: t("Chưa có chứng chỉ.") })]));
      list.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [t("Tên miền"), t("Cấp bởi"), t("Hiệu lực"), t("Dùng cho"), ""].map(th))]), tb])]));
      list.appendChild(form);
    }).catch(function (e) { toast(e.message, true); });
  }

  // ---------- users (admins) ----------
  function usersView(v) {
    v.appendChild(el("h1", { text: t("Người dùng console") }));
    var list = el("div"); v.appendChild(list);
    function load() {
      api("GET", "/api/open/users").then(function (d) {
        clear(list);
        var tb = el("tbody");
        (d.data || []).forEach(function (u) {
          var roleSel = select("", [["admin", t("Quản trị")], ["viewer", t("Chỉ xem")]], u.role); roleSel.removeAttribute("id");
          roleSel.addEventListener("change", function () {
            api("PUT", "/api/open/users", { username: u.username, role: roleSel.value }).then(function () { toast(t("Đã đổi quyền {0}", u.username)); load(); }, function (x) { toast(x.message, true); load(); });
          });
          tb.appendChild(el("tr", {}, [
            el("td", {}, [el("b", { text: u.username })]), el("td", {}, [roleSel]),
            el("td", {}, [el("span", { class: "pill " + (u.totp ? "ok" : "warn"), text: u.totp ? t("Đã bật") : t("Chưa bật") })]),
            el("td", { text: u.last_login ? fmtTime(u.last_login) : "–" }),
            el("td", {}, [
              u.totp ? el("button", { class: "btn small", text: t("Reset 2FA"), onclick: function () {
                if (confirm(t("Tắt xác thực 2 lớp của {0}?", u.username))) api("PUT", "/api/open/users", { username: u.username, reset_totp: true }).then(function () { toast(t("Đã reset 2FA")); load(); }, function (x) { toast(x.message, true); });
              } }) : null, " ",
              el("button", { class: "btn small", text: t("Đặt mật khẩu"), onclick: function () {
                var p = prompt(t("Mật khẩu mới cho {0} (≥ 10 ký tự):", u.username)); if (!p) return;
                api("PUT", "/api/open/users", { username: u.username, password: p }).then(function () { toast(t("Đã đổi mật khẩu")); }, function (x) { toast(x.message, true); });
              } }), " ",
              el("button", { class: "btn danger small", text: t("Xoá"), onclick: function () {
                if (confirm(t("Xoá người dùng {0}?", u.username))) api("DELETE", "/api/open/users", { usernames: [u.username] }).then(function () { toast(t("Đã xoá")); load(); }, function (x) { toast(x.message, true); });
              } })])]));
        });
        if (!(d.data || []).length) tb.appendChild(el("tr", {}, [el("td", { colspan: "5", class: "muted", text: t("Chưa có tài khoản; đang dùng API token. Hãy tạo tài khoản quản trị đầu tiên.") })]));
        list.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [t("Tên đăng nhập"), t("Quyền"), t("Xác thực 2 lớp"), t("Đăng nhập gần nhất"), ""].map(th))]), tb])]));
        var f = el("form", {}, [el("fieldset", {}, [el("legend", { text: t("Thêm người dùng") }), el("div", { class: "grid2" }, [
          field(t("Tên đăng nhập"), el("input", { id: "u-name", autocomplete: "off" })),
          field(t("Mật khẩu"), el("input", { id: "u-pass", type: "password", autocomplete: "new-password" }), t("Tối thiểu 10 ký tự.")),
          field(t("Quyền"), select("u-role", [["viewer", t("Chỉ xem")], ["admin", t("Quản trị")]], "viewer"))]),
          el("div", { class: "spacer" }), el("button", { type: "submit", class: "btn primary", text: t("Tạo") })])]);
        f.addEventListener("submit", function (e) {
          e.preventDefault();
          api("POST", "/api/open/users", { username: $("u-name").value.trim(), password: $("u-pass").value, role: $("u-role").value })
            .then(function () { toast(t("Đã tạo người dùng")); load(); }, function (x) { toast(x.message, true); });
        });
        list.appendChild(f);
      }).catch(function (e) { toast(e.message, true); });
    }
    load();
  }

  // ---------- system: backup, restore, audit ----------
  function systemView(v) {
    v.appendChild(el("h1", { text: t("Hệ thống") }));
    var restoreInput = el("input", { type: "file", accept: ".json,application/json" });
    v.appendChild(el("fieldset", {}, [el("legend", { text: t("Sao lưu & khôi phục cấu hình") }),
      el("p", { class: "muted", text: t("File sao lưu chứa toàn bộ ứng dụng và chứng chỉ (kèm private key) – hãy lưu trữ an toàn.") }),
      el("div", { class: "row" }, [
        el("button", { class: "btn primary", text: t("Tải file sao lưu"), onclick: function () {
          api("GET", "/api/open/backup").then(function (d) {
            var blob = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" });
            var a = el("a", { href: URL.createObjectURL(blob), download: "hcw-waf-backup-" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-") + ".json" });
            document.body.appendChild(a); a.click(); a.remove(); toast(t("Đã tải file sao lưu"));
          }, function (x) { toast(x.message, true); });
        } }),
        el("span", { class: "spacer" }), restoreInput,
        el("button", { class: "btn danger", text: t("Khôi phục từ file"), onclick: function () {
          var f = restoreInput.files[0]; if (!f) { toast(t("Chọn file sao lưu trước"), true); return; }
          if (!confirm(t("Thay toàn bộ cấu hình hiện tại bằng nội dung file {0}?", f.name))) return;
          var rd = new FileReader();
          rd.onload = function () {
            var data; try { data = JSON.parse(rd.result); } catch (e) { toast(t("File không phải JSON hợp lệ"), true); return; }
            api("POST", "/api/open/restore", data).then(function (r) { toast(t("Đã khôi phục {0} ứng dụng, {1} chứng chỉ", r.sites, r.certs)); route(); }, function (x) { toast(x.message, true); });
          };
          rd.readAsText(f);
        } })])]));
    v.appendChild(el("h2", { text: t("Nhật ký thao tác") }));
    var box = el("div"); v.appendChild(box);
    api("GET", "/api/open/audit?limit=300").then(function (d) {
      var tb = el("tbody");
      (d.data || []).forEach(function (e) {
        var detail = e.detail ? JSON.stringify(e.detail) : "";
        tb.appendChild(el("tr", {}, [el("td", { class: "nowrap", text: fmtTime(e.time) }), el("td", { text: e.user }), el("td", { class: "mono nowrap", text: e.ip }),
          el("td", { class: "mono nowrap", text: e.action }),
          el("td", {}, [el("span", { class: "pill " + (e.status < 400 ? "ok" : "bad"), text: String(e.status) })]),
          el("td", { class: "mono", text: detail.length > 160 ? detail.slice(0, 160) + "…" : detail })]));
      });
      if (!(d.data || []).length) tb.appendChild(el("tr", {}, [el("td", { colspan: "6", class: "muted", text: t("Chưa có thao tác nào.") })]));
      box.appendChild(el("div", { class: "table-wrap" }, [el("table", {}, [el("thead", {}, [el("tr", {}, [t("Thời gian"), tc("col", "Người dùng"), t("IP"), t("Thao tác"), t("Kết quả"), t("Chi tiết")].map(th))]), tb])]));
    }, function (x) { toast(x.message, true); });
  }

  // ---------- my account ----------
  function accountView(v) {
    v.appendChild(el("h1", { text: t("Tài khoản của tôi") }));
    var me = state.me || {};
    if (!me.account) {
      v.appendChild(el("p", { class: "muted", text: t("Bạn đang đăng nhập bằng API token. Tạo tài khoản ở trang Người dùng rồi đăng nhập bằng tài khoản để dùng mật khẩu và xác thực 2 lớp.") }));
      return;
    }
    var pw = el("form", {}, [el("fieldset", {}, [el("legend", { text: t("Đổi mật khẩu") }), el("div", { class: "grid2" }, [
      field(t("Mật khẩu hiện tại"), el("input", { id: "a-cur", type: "password", autocomplete: "current-password" })),
      field(t("Mật khẩu mới"), el("input", { id: "a-new", type: "password", autocomplete: "new-password" }), t("Tối thiểu 10 ký tự."))]),
      el("div", { class: "spacer" }), el("button", { type: "submit", class: "btn primary", text: t("Đổi mật khẩu") })])]);
    pw.addEventListener("submit", function (e) {
      e.preventDefault();
      api("POST", "/api/open/me/password", { current: $("a-cur").value, new: $("a-new").value }).then(function () { toast(t("Đã đổi mật khẩu")); $("a-cur").value = $("a-new").value = ""; }, function (x) { toast(x.message, true); });
    });
    var tf = el("fieldset", {}, [el("legend", { text: t("Xác thực 2 lớp (TOTP)") })]);
    function render2fa() {
      while (tf.childNodes.length > 1) tf.removeChild(tf.lastChild);
      if (me.totp) {
        tf.appendChild(el("p", {}, [el("span", { class: "pill ok", text: t("Đang bật") }), " " + t("Mỗi lần đăng nhập cần mã 6 số từ ứng dụng xác thực.")]));
        var code = el("input", { placeholder: t("Mã hiện tại để tắt"), inputmode: "numeric", maxlength: "6" });
        tf.appendChild(el("div", { class: "row" }, [code, el("button", { type: "button", class: "btn danger", text: t("Tắt 2FA"), onclick: function () {
          api("POST", "/api/open/me/totp/disable", { code: code.value.trim() }).then(function () { me.totp = false; toast(t("Đã tắt 2FA")); render2fa(); }, function (x) { toast(x.message, true); });
        } })]));
        return;
      }
      tf.appendChild(el("p", { class: "muted", text: t("Dùng Google Authenticator, Microsoft Authenticator hoặc Authy để bảo vệ tài khoản.") }));
      tf.appendChild(el("button", { type: "button", class: "btn primary", text: t("Bật xác thực 2 lớp"), onclick: function () {
        api("POST", "/api/open/me/totp/setup").then(function (d) {
          while (tf.childNodes.length > 1) tf.removeChild(tf.lastChild);
          tf.appendChild(el("p", { text: t("1. Quét mã QR bằng ứng dụng xác thực:") }));
          tf.appendChild(el("img", { class: "qr", src: d.qr, alt: "QR" }));
          tf.appendChild(el("p", {}, [t("Hoặc nhập khoá:") + " ", el("code", { class: "mono", text: d.secret })]));
          tf.appendChild(el("p", { text: t("2. Nhập mã 6 số đang hiển thị để xác nhận:") }));
          var code = el("input", { id: "a-otp", inputmode: "numeric", maxlength: "6" });
          tf.appendChild(el("div", { class: "row" }, [code, el("button", { type: "button", class: "btn primary", text: t("Xác nhận"), onclick: function () {
            api("POST", "/api/open/me/totp/enable", { code: code.value.trim() }).then(function () { me.totp = true; toast(t("Đã bật 2FA")); render2fa(); }, function (x) { toast(x.message, true); });
          } })]));
        }, function (x) { toast(x.message, true); });
      } }));
    }
    render2fa();
    v.appendChild(pw); v.appendChild(tf);
  }

  show();
})();
