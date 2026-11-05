// Panel Smart Stock v4. Solo usa la clave publicable: toda operación pasa por funciones que validan rol en el servidor.
(() => {
  "use strict";
  const { url, key } = window.SS_CONFIG;
  const HOME = location.origin + location.pathname;
  // Se lee antes de crear el cliente: el cliente limpia la dirección al tomar la sesión.
  const landing = new URLSearchParams(location.hash.slice(1));
  const linkType = landing.get("type");
  const linkError = landing.get("error_code") || landing.get("error");
  let mustSetPassword = linkType === "recovery" || linkType === "invite";
  const db = window.supabase.createClient(url, key, {
    auth: { storage: window.sessionStorage, persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
  });

  const IDLE_MS = 30 * 60 * 1000;
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n ?? 0).toLocaleString("es-AR");
  const when = (d) => (d ? new Date(d).toLocaleString("es-AR", { dateStyle: "short", timeStyle: "short" }) : "—");
  const signed = (n) => (n > 0 ? `+${n}` : String(n));
  const uuid = () => crypto.randomUUID();
  const ROLE = { admin: "Administrador", operator: "Operador de inventario", viewer: "Consulta", pending: "Pendiente" };

  const state = { user: null, role: null, dash: null, groups: [], staged: new Map(), rowState: new Map(), filters: { q: "", style: "", color: "", status: "pending" }, includeTest: false, mov: { types: [], q: "", from: "", to: "", page: 0 } };
  const staff = () => state.role === "admin" || state.role === "operator";
  const admin = () => state.role === "admin";

  async function call(fn, args) {
    const { data, error } = await db.rpc(fn, args);
    if (error) {
      if (error.code === "42501" || /JWT|permission denied/i.test(error.message)) { await refreshRole(); }
      throw new Error(error.message);
    }
    return data;
  }
  function toast(text, bad) {
    const t = $("#toast"); t.textContent = text; t.className = "toast on" + (bad ? " bad" : "");
    clearTimeout(toast.t); toast.t = setTimeout(() => { t.className = "toast"; }, 4200);
  }
  function fail(e) { toast(e.message || "Ocurrió un error", true); }

  /* ---------- Sesión ---------- */
  let signup = false, idle;
  if (!window.SS_CONFIG.signupOpen) {
    $("#authToggle").hidden = true;
    $("#authSep").hidden = true;
    $("#authFine").textContent = "Las cuentas se crean por invitación de un administrador.";
  }
  function touch() { clearTimeout(idle); if (state.user) idle = setTimeout(() => { db.auth.signOut(); toast("Sesión cerrada por inactividad"); }, IDLE_MS); }
  ["pointerdown", "keydown"].forEach((e) => addEventListener(e, touch, { passive: true }));

  function show(id) { ["boot", "auth", "setpw", "pending", "app"].forEach((x) => { $("#" + x).hidden = x !== id; }); }

  async function refreshRole() {
    const { data: role } = await db.rpc("ss_current_role");
    state.role = role ?? "pending";
  }
  async function onSession(session) {
    if (!session) { state.user = null; state.role = null; state.staged.clear(); show("auth"); return; }
    if (mustSetPassword) { state.user = session.user; show("setpw"); return; }
    if (state.user?.id === session.user.id && state.role) return;
    state.user = session.user;
    await refreshRole();
    touch();
    if (!["admin", "operator", "viewer"].includes(state.role)) { $("#pendingEmail").textContent = session.user.email; show("pending"); return; }
    $("#meEmail").textContent = session.user.email; $("#meRole").textContent = ROLE[state.role];
    show("app"); drawNav(); await loadDash(); route();
  }
  db.auth.onAuthStateChange((e, s) => {
    if (e === "PASSWORD_RECOVERY") mustSetPassword = true;
    setTimeout(() => onSession(s), 0);
  });

  $("#pwForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const m = $("#pwMsg"), a = $("#pw1").value, b = $("#pw2").value;
    m.className = "msg"; m.textContent = "";
    if (a.length < 10) { m.textContent = "Usá 10 caracteres o más."; return; }
    if (a !== b) { m.textContent = "Las contraseñas no coinciden."; return; }
    $("#pwSubmit").disabled = true;
    const { data, error } = await db.auth.updateUser({ password: a });
    $("#pwSubmit").disabled = false;
    if (error) { m.textContent = error.message; return; }
    $("#pw1").value = ""; $("#pw2").value = "";
    mustSetPassword = false; state.user = null;
    history.replaceState(null, "", HOME);
    toast("Contraseña guardada");
    await onSession({ user: data.user });
  });

  $("#authForgot").addEventListener("click", async () => {
    const msg = $("#authMsg"), email = $("#email").value.trim();
    msg.className = "msg"; msg.textContent = "";
    if (!email) { msg.textContent = "Escribí tu correo y volvé a tocar «Olvidé mi contraseña»."; return; }
    const { error } = await db.auth.resetPasswordForEmail(email, { redirectTo: HOME });
    if (error && error.status === 429) { msg.textContent = "Demasiados pedidos. Probá más tarde."; return; }
    msg.className = "msg good"; msg.textContent = "Si la cuenta existe, te llega un correo con el enlace.";
  });

  if (linkError) {
    $("#authMsg").textContent = linkError === "otp_expired" ? "El enlace venció o ya se usó. Pedí uno nuevo." : "No se pudo validar el enlace. Pedí uno nuevo.";
    history.replaceState(null, "", HOME);
  }

  $("#authToggle").addEventListener("click", () => {
    signup = !signup;
    $("#authSubmit").textContent = signup ? "Crear cuenta" : "Ingresar";
    $("#authToggle").textContent = signup ? "Ya tengo cuenta" : "Solicitar acceso";
    $("#password").autocomplete = signup ? "new-password" : "current-password";
    $("#authMsg").textContent = "";
  });
  $("#authForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const msg = $("#authMsg"), email = $("#email").value.trim(), password = $("#password").value;
    msg.className = "msg"; msg.textContent = "";
    if (!email || password.length < 10) { msg.textContent = "Ingresá el correo y una contraseña de 10 caracteres o más."; return; }
    const b = $("#authSubmit"); b.disabled = true;
    try {
      if (signup) {
        const { error } = await db.auth.signUp({ email, password, options: { emailRedirectTo: HOME } });
        if (error) throw error;
        msg.className = "msg good"; msg.textContent = "Revisá tu correo para confirmar la cuenta. Después un administrador te da acceso.";
      } else {
        const { error } = await db.auth.signInWithPassword({ email, password });
        if (error) throw new Error("Correo o contraseña incorrectos, o cuenta sin confirmar.");
      }
      $("#password").value = "";
    } catch (e) { msg.textContent = e.message; } finally { b.disabled = false; }
  });
  document.addEventListener("click", (e) => { if (e.target.closest("[data-signout]")) db.auth.signOut(); });

  /* ---------- Navegación ---------- */
  const VIEWS = {
    resumen: ["Resumen", viewResumen], conteo: ["Conteo", viewConteo], movimientos: ["Historial", viewMovimientos],
    ventas: ["Ventas", viewVentas], conciliacion: ["Conciliación", viewConciliacion], alertas: ["Alertas", viewAlertas],
    usuarios: ["Usuarios", viewUsuarios],
  };
  function drawNav() {
    const cur = (location.hash || "#resumen").slice(1);
    const a = state.dash?.alerts_critical ?? 0;
    $("#nav").innerHTML = Object.entries(VIEWS).filter(([k]) => k !== "usuarios" || admin()).map(([k, [label]]) =>
      `<a href="#${k}" ${k === cur ? 'aria-current="page"' : ""}>${label}${k === "alertas" && a ? `<span class="dot">${a}</span>` : ""}</a>`).join("");
  }
  async function route() {
    if (!state.user || $("#app").hidden) return;
    let cur = (location.hash || "#resumen").slice(1);
    if (!VIEWS[cur] || (cur === "usuarios" && !admin())) cur = "resumen";
    const v = $("#view");
    try { await loadDash(); } catch (e) {
      await refreshRole();
      if (!["admin", "operator", "viewer"].includes(state.role)) { $("#pendingEmail").textContent = state.user.email; show("pending"); return; }
    }
    if (cur === "usuarios" && !admin()) { location.hash = "#resumen"; return; }
    v.innerHTML = `<p class="skeleton">Cargando ${esc(VIEWS[cur][0].toLowerCase())}…</p>`;
    try { await VIEWS[cur][1](v); } catch (e) { v.innerHTML = `<div class="err-box">No se pudo cargar: ${esc(e.message)} <button class="link" data-retry>Reintentar</button></div>`; }
    window.scrollTo(0, 0);
  }
  addEventListener("hashchange", route);
  document.addEventListener("click", (e) => { if (e.target.closest("[data-retry]")) route(); });

  async function loadDash() {
    state.dash = await call("ss_dashboard");
    // El rol manda en el servidor; acá solo se mantiene al día lo que se ve.
    if (state.dash.role !== state.role) { state.role = state.dash.role; $("#meRole").textContent = ROLE[state.role] ?? state.role; }
    drawStatus(); drawNav();
  }
  function drawStatus() {
    const d = state.dash, h = d.health;
    const lamp = h.worker_stale ? "bad" : "ok";
    const pend = d.orders_pending;
    $("#status").innerHTML = `
      <span><i class="lamp ${lamp}"></i>Worker <b>${h.worker_stale ? "detenido" : "activo"}</b></span>
      <span class="opt">Último ciclo <b>${esc(when(h.worker_last_ok))}</b></span>
      <span><i class="lamp ${pend ? "bad" : "ok"}"></i>Pedidos sin conciliar <b>${pend}</b></span>
      <span><i class="lamp ${d.products_enabled ? "warn" : ""}"></i>Ventas <b>${d.products_enabled ? d.products_enabled + " productos activos" : "desactivadas"}</b></span>`;
  }

  /* ---------- Resumen ---------- */
  async function viewResumen(v) {
    const d = state.dash, h = d.health;
    v.innerHTML = `
      <div class="head"><div><h1>Resumen</h1><p>Tres saldos que nunca se suman entre sí.</p></div></div>
      <div class="ledger">
        <section><h2>Histórico sin contar</h2><div class="big num">${num(d.units_historic)}</div><p>${d.groups_unverified} ${d.groups_unverified === 1 ? "grupo" : "grupos"}. No se venden ni se dan por existentes.</p></section>
        <section><h2>Físico confirmado</h2><div class="big num">${num(d.units_confirmed)}</div><p>${d.groups_verified} grupos contados. ${num(d.units_reserved)} reservadas, ${num(d.units_available)} disponibles.</p></section>
        <section><h2>Comercial publicado</h2><div class="big num sold">${num(d.units_sellable)}</div><p>Vendible por stock. Solo se publica si el producto está autorizado.</p></section>
      </div>
      <h2>Estado</h2>
      <dl class="facts">
        ${fact("Productos", d.products_total)}${fact("Variantes", d.variants_total)}${fact("Grupos físicos", d.groups_total)}
        ${fact("Grupos sin contar", d.groups_unverified, d.groups_unverified ? "warn" : "ok")}${fact("Grupos confirmados", d.groups_verified)}
        ${fact("Productos a la venta", d.products_enabled)}${fact("Alertas abiertas", d.alerts_open, d.alerts_critical ? "bad" : d.alerts_open ? "warn" : "ok")}
        ${fact("Alertas críticas", d.alerts_critical, d.alerts_critical ? "bad" : "ok")}${fact("Pedidos sin conciliar", d.orders_pending, d.orders_pending ? "bad" : "ok")}
        ${fact("Worker", h.worker_stale ? "Detenido" : "Activo", h.worker_stale ? "bad" : "ok")}
        ${fact("Circuito (ss_health)", h.ok ? "Correcto" : "Con problemas", h.ok ? "ok" : "bad")}
        ${fact("Última lectura de Tiendanube", when(h.last_live_check))}${fact("Última publicación", when(d.last_sync))}
      </dl>
      ${d.groups_unverified ? `<div class="note-box">El circuito puede estar correcto y no haber nada para vender: faltan ${d.groups_unverified} grupos por contar.</div>` : ""}
      ${staff() && d.groups_unverified ? `<p><a class="btn gold as-link" href="#conteo">Empezar conteo</a></p>` : ""}`;
  }
  const fact = (k, val, c = "") => `<div><dt>${esc(k)}</dt><dd class="${c}">${esc(val)}</dd></div>`;

  /* ---------- Conteo ---------- */
  async function viewConteo(v) {
    state.groups = await call("ss_panel_groups", { p_include_test: state.includeTest });
    const styles = [...new Set(state.groups.map((g) => g.style))], colors = [...new Set(state.groups.map((g) => g.color.toLowerCase()))].sort();
    const f = state.filters;
    v.innerHTML = `
      <div class="head"><div><h1>Conteo físico</h1><p>${staff() ? "Cargá lo que contaste. Nada se guarda hasta que revises y confirmes." : "Solo lectura."} Contar no habilita ventas.</p></div>
        <div class="actions"><button class="btn small" id="csvOut">Exportar CSV</button>${staff() ? `<label class="btn small" for="csvIn">Importar CSV</label><input id="csvIn" type="file" accept=".csv,text/csv" hidden>` : ""}</div></div>
      <div class="filters">
        <label>Buscar <input id="fq" type="search" value="${esc(f.q)}" placeholder="SKU, prenda, color"></label>
        <label>Prenda <select id="fs"><option value="">Todas</option>${styles.map((s) => `<option ${s === f.style ? "selected" : ""}>${esc(s)}</option>`).join("")}</select></label>
        <label>Color <select id="fc"><option value="">Todos</option>${colors.map((s) => `<option ${s === f.color ? "selected" : ""}>${esc(s)}</option>`).join("")}</select></label>
        <label>Estado <select id="fe"><option value="">Todos</option><option value="pending" ${f.status === "pending" ? "selected" : ""}>Sin contar</option><option value="done" ${f.status === "done" ? "selected" : ""}>Confirmados</option></select></label>
      </div>
      ${admin() ? `<label class="check gap"><input type="checkbox" id="ft" ${state.includeTest ? "checked" : ""}> Mostrar grupos de prueba</label>` : ""}
      <div id="rows"></div><div id="bar"></div>`;
    const set = (id, k) => $(id).addEventListener("input", (e) => { f[k] = e.target.value; drawRows(); });
    set("#fq", "q"); set("#fs", "style"); set("#fc", "color"); set("#fe", "status");
    $("#ft")?.addEventListener("change", (e) => { state.includeTest = e.target.checked; route(); });
    $("#csvOut").addEventListener("click", exportCsv);
    $("#csvIn")?.addEventListener("change", importCsv);
    drawRows();
  }
  function visibleGroups() {
    const f = state.filters, q = f.q.trim().toLowerCase();
    return state.groups.filter((g) => (!f.style || g.style === f.style) && (!f.color || g.color.toLowerCase() === f.color)
      && (!f.status || (f.status === "pending" ? !g.stock_verified : g.stock_verified))
      && (!q || `${g.sku} ${g.style} ${g.color} ${g.size}`.toLowerCase().includes(q)));
  }
  function drawRows() {
    const rows = visibleGroups(), box = $("#rows");
    if (!box) return;
    if (!rows.length) { box.innerHTML = `<p class="empty">No hay grupos con esos filtros.</p>`; drawBar(); return; }
    box.innerHTML = `<table class="rows count-table"><thead><tr><th>Grupo</th><th>SKU</th><th class="n">Histórico</th><th class="n">Reservado</th><th class="n">Contado</th><th class="n">Diferencia</th><th class="hide-md">Observaciones</th><th>Estado</th></tr></thead><tbody>
      ${rows.map(rowHtml).join("")}</tbody></table>`;
    drawBar();
  }
  function rowHtml(g) {
    const s = state.staged.get(g.id), st = state.rowState.get(g.id);
    const val = s ? s.counted : "", diff = s ? s.counted - g.quantity : null;
    const status = st?.text ? `<span class="tag ${st.cls}">${esc(st.text)}</span>` : g.stock_verified ? `<span class="tag ok">Contado</span>` : `<span class="tag warn">Sin contar</span>`;
    const last = g.last_count_at ? `<div class="sub">${esc(when(g.last_count_at))}${g.last_count_by ? " · " + esc(g.last_count_by) : ""}</div>` : "";
    return `<tr data-id="${esc(g.id)}" class="${st?.row ?? (s ? "staged" : "")}">
      <td class="c-grp"><div class="main">${esc(g.style)} · ${esc(g.color)} · ${esc(g.size)}</div><div class="sub">${esc(g.sku)}</div></td>
      <td class="hide-sm">${esc(g.sku)}</td>
      <td class="n c-hist" data-l="Histórico">${num(g.quantity)}</td>
      <td class="n c-res" data-l="Reservado">${num(g.reserved)}</td>
      <td class="n c-in" data-l="Contado">${staff() ? `<input class="count-in" inputmode="numeric" pattern="[0-9]*" maxlength="6" aria-label="Cantidad contada de ${esc(g.sku)}" placeholder="Contado" value="${esc(val)}">` : "—"}</td>
      <td class="n c-diff" data-l="Diferencia"><span class="diff ${diff > 0 ? "pos" : diff < 0 ? "neg" : ""}">${diff === null ? "—" : signed(diff)}</span></td>
      <td class="hide-md wide c-note">${staff() ? `<input class="note-in" maxlength="300" aria-label="Observaciones de ${esc(g.sku)}" placeholder="Observaciones (opcional)" value="${esc(s?.note ?? "")}">` : esc(g.last_note ?? "")}</td>
      <td class="wide">${status}${last}</td></tr>`;
  }
  document.addEventListener("input", (e) => {
    const tr = e.target.closest?.("tr[data-id]"); if (!tr) return;
    const id = tr.dataset.id, g = state.groups.find((x) => x.id === id);
    if (e.target.classList.contains("count-in")) {
      const raw = e.target.value.trim();
      const ok = /^\d{1,6}$/.test(raw);
      e.target.setAttribute("aria-invalid", raw && !ok ? "true" : "false");
      const prev = state.staged.get(id);
      state.rowState.delete(id);
      if (!ok) { state.staged.delete(id); tr.className = ""; tr.querySelector(".diff").textContent = "—"; tr.querySelector(".diff").className = "diff"; drawBar(); return; }
      const counted = Number(raw);
      // Misma cantidad, misma solicitud: reintentar nunca duplica. Otra cantidad es otra solicitud.
      state.staged.set(id, { counted, note: prev?.note ?? tr.querySelector(".note-in")?.value ?? "", request_id: prev?.counted === counted ? prev.request_id : uuid(), expected_updated_at: g.updated_at });
      const d = counted - g.quantity, el = tr.querySelector(".diff");
      el.textContent = signed(d); el.className = "diff " + (d > 0 ? "pos" : d < 0 ? "neg" : "");
      if (!tr.classList.contains("staged")) tr.className = "staged"; drawBar();
    } else if (e.target.classList.contains("note-in")) {
      const s = state.staged.get(id); if (s) s.note = e.target.value;
    }
  });
  function drawBar() {
    const n = state.staged.size, b = $("#bar"); if (!b) return;
    b.innerHTML = n ? `<div class="bar"><span>${n} ${n === 1 ? "grupo cargado" : "grupos cargados"}</span><span class="actions"><button class="btn small" id="clr">Descartar</button><button class="btn gold small" id="rev">Revisar y confirmar</button></span></div>` : "";
    $("#clr")?.addEventListener("click", () => { state.staged.clear(); state.rowState.clear(); drawRows(); });
    $("#rev")?.addEventListener("click", reviewCounts);
  }
  function reviewCounts() {
    const items = [...state.staged.entries()].map(([id, s]) => ({ g: state.groups.find((x) => x.id === id), s }));
    const dlg = $("#dlg");
    dlg.innerHTML = `<h2>Revisar ${items.length} ${items.length === 1 ? "conteo" : "conteos"}</h2>
      <p>Cada uno queda registrado a tu nombre y reemplaza la cantidad histórica. Las ventas no cambian.</p>
      <div class="dlg-list">${items.map(({ g, s }) => { const d = s.counted - g.quantity; return `<div><span>${esc(g.style)} · ${esc(g.color)} · ${esc(g.size)}</span><span class="num">${num(g.quantity)} → <b>${num(s.counted)}</b> <span class="diff ${d > 0 ? "pos" : d < 0 ? "neg" : ""}">(${signed(d)})</span></span></div>`; }).join("")}</div>
      <label class="check"><input type="checkbox" id="real"> Confirmo que son unidades contadas físicamente.</label>
      <div class="dlg-actions"><button class="btn" id="no">Volver</button><button class="btn gold" id="yes" disabled>Registrar conteos</button></div>`;
    dlg.showModal();
    $("#real").addEventListener("change", (e) => { $("#yes").disabled = !e.target.checked; });
    $("#no").addEventListener("click", () => dlg.close());
    $("#yes").addEventListener("click", async () => {
      $("#yes").disabled = true; $("#yes").textContent = "Registrando…";
      try { await submitCounts(items); dlg.close(); } catch (e) { dlg.close(); fail(e); }
    });
  }
  async function submitCounts(items) {
    const payload = items.map(({ g, s }) => ({ id: g.id, counted: s.counted, note: s.note, request_id: s.request_id, expected_updated_at: s.expected_updated_at }));
    const res = await call("ss_submit_count_batch", { p_batch: uuid(), p_items: payload });
    const fresh = await call("ss_panel_groups", { p_include_test: state.includeTest });
    state.groups = fresh;
    for (const r of res.results) {
      if (r.status === "ok" || r.status === "duplicate") {
        state.staged.delete(r.id);
        state.rowState.set(r.id, { text: r.status === "ok" ? `Registrado (${signed(r.difference)})` : "Ya estaba registrado", cls: "ok", row: "done" });
      } else {
        state.rowState.set(r.id, { text: r.message, cls: "bad", row: "fail" });
        const s = state.staged.get(r.id), g = fresh.find((x) => x.id === r.id);
        if (r.status === "conflict" && s && g) { s.expected_updated_at = g.updated_at; s.request_id = uuid(); }
      }
    }
    if (state.filters.status === "pending") state.filters.status = "";
    if ($("#fe")) $("#fe").value = state.filters.status;
    drawRows(); await loadDash();
    toast(`${res.ok === 1 ? "1 registrado" : res.ok + " registrados"}${res.duplicate ? `, ${res.duplicate} repetidos` : ""}${res.failed ? `, ${res.failed} con error` : ""}`, res.failed > 0);
  }

  /* CSV */
  const cell = (v) => {
    let s = String(v ?? "");
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // evita fórmulas al abrir en planillas
    return /[",;\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  function download(name, text) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob(["﻿" + text], { type: "text/csv;charset=utf-8" }));
    a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  function exportCsv() {
    const head = ["sku", "prenda", "color", "talle", "historico", "reservado", "contado", "observaciones"];
    const lines = visibleGroups().map((g) => [g.sku, g.style, g.color, g.size, g.quantity, g.reserved, "", ""].map(cell).join(","));
    download(`conteo-smart-stock-${new Date().toISOString().slice(0, 10)}.csv`, [head.join(","), ...lines].join("\r\n"));
  }
  function parseCsv(text) {
    text = text.replace(/^﻿/, "");
    const first = text.split(/\r?\n/, 1)[0], sep = (first.match(/;/g) || []).length > (first.match(/,/g) || []).length ? ";" : ",";
    const rows = []; let row = [], c = "", q = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (q) { if (ch === '"') { if (text[i + 1] === '"') { c += '"'; i++; } else q = false; } else c += ch; }
      else if (ch === '"') q = true;
      else if (ch === sep) { row.push(c); c = ""; }
      else if (ch === "\n") { row.push(c.replace(/\r$/, "")); rows.push(row); row = []; c = ""; }
      else c += ch;
    }
    if (c || row.length) { row.push(c); rows.push(row); }
    return rows.filter((r) => r.some((x) => x.trim()));
  }
  async function importCsv(ev) {
    const file = ev.target.files[0]; ev.target.value = "";
    if (!file) return;
    try {
      if (file.size > 200 * 1024) throw new Error("El archivo es demasiado grande");
      const rows = parseCsv(await file.text());
      const head = (rows.shift() ?? []).map((h) => h.trim().toLowerCase());
      const iS = head.indexOf("sku"), iC = head.indexOf("contado"), iN = head.indexOf("observaciones");
      if (iS < 0 || iC < 0) throw new Error("Faltan las columnas sku y contado");
      const data = rows.map((r, i) => ({ line: i + 2, sku: r[iS] ?? "", counted: r[iC] ?? "", note: iN >= 0 ? r[iN] ?? "" : "" })).filter((r) => r.counted.trim() !== "");
      if (!data.length) throw new Error("El archivo no tiene cantidades cargadas");
      const res = await call("ss_validate_count_import", { p_rows: data.map(({ note, ...r }) => r) });
      const dlg = $("#dlg");
      if (!res.valid) {
        dlg.innerHTML = `<h2>Archivo rechazado</h2><p>No se aplicó ningún cambio. Corregí estas filas:</p>
          <div class="dlg-list">${res.rows.filter((r) => r.error).map((r) => `<div><span>Fila ${esc(r.line)}${r.sku ? " · " + esc(r.sku) : ""}</span><span class="diff neg">${esc(r.error)}</span></div>`).join("")}</div>
          <div class="dlg-actions"><button class="btn" id="no">Cerrar</button></div>`;
        dlg.showModal(); $("#no").addEventListener("click", () => dlg.close()); return;
      }
      res.rows.forEach((r, i) => state.staged.set(r.id, { counted: r.counted, note: data[i].note || "Importado de CSV", request_id: uuid(), expected_updated_at: r.updated_at }));
      state.filters.status = ""; $("#fe").value = ""; drawRows();
      toast(`${res.rows.length === 1 ? "1 fila válida" : res.rows.length + " filas válidas"}. Revisá y confirmá para registrar.`);
    } catch (e) { fail(e); }
  }

  /* ---------- Historial ---------- */
  const MOV = { receipt: "Entrada", initial: "Inicial", manual: "Manual", sale: "Venta", reservation: "Reserva", release: "Liberación", restock: "Restitución", cancellation: "Cancelación", physical_count: "Conteo físico", adjustment: "Ajuste", reconciliation: "Conciliación" };
  async function viewMovimientos(v) {
    v.innerHTML = `<div class="head"><div><h1>Historial</h1><p>Registro contable inmutable: nadie puede editarlo ni borrarlo.</p></div></div>
      <div class="chips" id="chips">${Object.entries(MOV).map(([k, l]) => `<button class="chip" data-k="${k}" aria-pressed="${state.mov.types.includes(k)}">${l}</button>`).join("")}</div>
      <div class="filters"><label>Buscar <input id="mq" type="search" value="${esc(state.mov.q)}" placeholder="SKU, pedido, motivo"></label>
        <label>Desde <input id="mf" type="date" value="${esc(state.mov.from)}"></label><label>Hasta <input id="mt" type="date" value="${esc(state.mov.to)}"></label></div>
      <div id="movs"></div>`;
    $("#chips").addEventListener("click", (e) => {
      const b = e.target.closest(".chip"); if (!b) return;
      const on = b.getAttribute("aria-pressed") !== "true"; b.setAttribute("aria-pressed", on);
      state.mov.types = on ? [...state.mov.types, b.dataset.k] : state.mov.types.filter((x) => x !== b.dataset.k);
      state.mov.page = 0; loadMov();
    });
    let t; $("#mq").addEventListener("input", (e) => { state.mov.q = e.target.value; state.mov.page = 0; clearTimeout(t); t = setTimeout(loadMov, 300); });
    $("#mf").addEventListener("change", (e) => { state.mov.from = e.target.value; state.mov.page = 0; loadMov(); });
    $("#mt").addEventListener("change", (e) => { state.mov.to = e.target.value; state.mov.page = 0; loadMov(); });
    await loadMov();
  }
  async function loadMov() {
    const m = state.mov, size = 50, box = $("#movs");
    let to = null; if (m.to) { const d = new Date(m.to + "T00:00:00"); d.setDate(d.getDate() + 1); to = d.toISOString(); }
    try {
      const r = await call("ss_movements", { p_types: m.types.length ? m.types : null, p_stock: null, p_search: m.q || null, p_from: m.from ? new Date(m.from + "T00:00:00").toISOString() : null, p_to: to, p_limit: size, p_offset: m.page * size });
      const pages = Math.max(1, Math.ceil(r.total / size));
      box.innerHTML = !r.rows.length ? `<p class="empty">Sin movimientos con esos filtros.</p>` : `<table class="rows"><thead><tr><th>Fecha</th><th>Tipo</th><th>Grupo</th><th class="n">Cantidad</th><th class="n">Saldo</th><th class="hide-md">Usuario o proceso</th><th>Origen y motivo</th></tr></thead><tbody>
        ${r.rows.map((x) => `<tr><td class="wide">${esc(when(x.created_at))}</td><td data-l="Tipo">${esc(MOV[x.movement_type] ?? x.movement_type)}</td>
          <td class="wide"><div class="main">${esc(x.style)} · ${esc(x.color)} · ${esc(x.size)}</div><div class="sub">${esc(x.sku)}</div></td>
          <td class="n" data-l="Cantidad"><span class="diff ${x.delta > 0 ? "pos" : x.delta < 0 ? "neg" : ""}">${signed(x.delta)}</span>${x.reserved_delta ? `<div class="sub">res. ${signed(x.reserved_delta)}</div>` : ""}</td>
          <td class="n" data-l="Saldo">${num(x.quantity_before)} → ${num(x.quantity_after)}</td>
          <td class="hide-md wide">${esc(x.actor)}</td>
          <td class="wide">${esc(x.source)}${x.order_id ? ` · pedido ${esc(x.order_id)}` : ""}<div class="sub">${esc(x.detail)}</div></td></tr>`).join("")}</tbody></table>
        <div class="pager"><span>${num(r.total)} movimientos · página ${m.page + 1} de ${pages}</span><span class="actions"><button class="btn small" id="pv" ${m.page ? "" : "disabled"}>Anterior</button><button class="btn small" id="nx" ${m.page + 1 < pages ? "" : "disabled"}>Siguiente</button></span></div>`;
      $("#pv")?.addEventListener("click", () => { m.page--; loadMov(); });
      $("#nx")?.addEventListener("click", () => { m.page++; loadMov(); });
    } catch (e) { box.innerHTML = `<div class="err-box">${esc(e.message)}</div>`; }
  }

  /* ---------- Ventas ---------- */
  async function viewVentas(v) {
    const r = await call("ss_products_overview");
    const ap = (x, k, label) => `<div><dt>${label}</dt><dd class="${x?.approved ? "ok" : "warn"}">${x?.approved ? "Aprobado" : "Pendiente"}${admin() ? ` <button class="link" data-appr="${k}" data-val="${!x?.approved}">${x?.approved ? "Retirar" : "Aprobar"}</button>` : ""}</dd></div>`;
    v.innerHTML = `<div class="head"><div><h1>Control de ventas</h1><p>Autorización por producto, separada del conteo. Solo un administrador puede habilitar.</p></div></div>
      <dl class="facts">${ap(r.shipping, "shipping", "Logística")}${ap(r.payments, "payments", "Pagos y condiciones")}</dl>
      ${r.products.map((p) => { const miss = p.readiness.filter((x) => !x.ok); return `<article class="product">
        <div><h3>${esc(p.product_name)}</h3>
          <p class="meta">ID ${esc(p.product_id)} · ${p.variants} ${p.variants === 1 ? "variante" : "variantes"} · ${p.groups_verified} de ${p.groups} grupos contados<br>
          Precio: ${p.price_max ? `$ ${num(p.price_min)}${p.price_min !== p.price_max ? " a $ " + num(p.price_max) : ""}` : "sin precio"} · Última publicación: ${esc(when(p.last_sync))}</p>
          <p><span class="tag ${p.sales_enabled ? "ok" : "mute"}">${p.sales_enabled ? "A la venta" : "Ventas desactivadas"}</span></p>
          ${admin() ? (p.sales_enabled ? `<button class="btn wine" data-sale="${esc(p.product_id)}" data-on="false">Desactivar ventas</button>` : `<button class="btn" data-sale="${esc(p.product_id)}" data-on="true" ${miss.length ? "disabled" : ""}>Habilitar ventas</button>${miss.length ? `<p class="fine gap-t">${miss.length === 1 ? "Falta 1 requisito" : `Faltan ${miss.length} requisitos`}.</p>` : ""}`) : ""}
        </div>
        <ul class="checks">${p.readiness.map((x) => `<li><span class="${x.ok ? "y" : "x"}" aria-hidden="true">${x.ok ? "✓" : "✕"}</span><span>${esc(x.label)}<span class="sr"> ${x.ok ? "cumplido" : "falta"}</span></span><span class="d">${esc(x.detail)}</span></li>`).join("")}</ul>
      </article>`; }).join("") || `<p class="empty">No hay productos vinculados.</p>`}
      ${r.unmapped.length ? `<h2>Variantes pendientes de asociación</h2>${r.unmapped.map((u) => `<div class="alert critico"><div>${esc(u.subject)}<small>Corte «${esc(u.detail?.cut ?? "—")}» · Color «${esc(u.detail?.color ?? "—")}» · Talle «${esc(u.detail?.size ?? "—")}»</small></div></div>`).join("")}` : ""}`;
    v.querySelectorAll("[data-appr]").forEach((b) => b.addEventListener("click", () => approval(b.dataset.appr, b.dataset.val === "true")));
    v.querySelectorAll("[data-sale]").forEach((b) => b.addEventListener("click", () => sale(Number(b.dataset.sale), b.dataset.on === "true")));
  }
  function approval(key, val) {
    const dlg = $("#dlg");
    dlg.innerHTML = `<h2>${val ? "Aprobar" : "Retirar"} ${key === "shipping" ? "logística" : "pagos y condiciones"}</h2><p>Queda registrado a tu nombre. Esto no abre ventas por sí solo.</p>
      <label class="f">Motivo <textarea id="why" rows="2" maxlength="300"></textarea></label>
      <div class="dlg-actions"><button class="btn" id="no">Cancelar</button><button class="btn gold" id="yes">Confirmar</button></div>`;
    dlg.showModal(); $("#no").addEventListener("click", () => dlg.close());
    $("#yes").addEventListener("click", async () => {
      try { await call("ss_set_commercial_approval", { p_key: key, p_approved: val, p_note: $("#why").value }); dlg.close(); toast("Registrado"); route(); } catch (e) { fail(e); }
    });
  }
  function sale(id, on) {
    const dlg = $("#dlg");
    dlg.innerHTML = on ? `<h2>Habilitar ventas</h2><p>El producto se publica con el stock contado y empieza a venderse de verdad.</p>
      <label class="f">Escribí HABILITAR VENTAS para confirmar <input id="txt" autocomplete="off"></label>
      <div class="dlg-actions"><button class="btn" id="no">Cancelar</button><button class="btn gold" id="yes" disabled>Habilitar</button></div>`
      : `<h2>Desactivar ventas</h2><p>Tiendanube pasa a mostrar stock 0. Los pedidos existentes no cambian.</p><div class="dlg-actions"><button class="btn" id="no">Cancelar</button><button class="btn wine" id="yes">Desactivar</button></div>`;
    dlg.showModal(); $("#no").addEventListener("click", () => dlg.close());
    $("#txt")?.addEventListener("input", (e) => { $("#yes").disabled = e.target.value !== "HABILITAR VENTAS"; });
    $("#yes").addEventListener("click", async () => {
      try {
        const r = await call("ss_set_sales_authorization", { p_product: id, p_enabled: on, p_confirm: $("#txt")?.value ?? null });
        dlg.close();
        if (r.status === "blocked") toast("Bloqueado: " + r.missing.join(", "), true); else toast(on ? "Ventas habilitadas" : "Ventas desactivadas");
        await loadDash(); route();
      } catch (e) { dlg.close(); fail(e); }
    });
  }

  /* ---------- Conciliación ---------- */
  let onlyDiff = false;
  async function viewConciliacion(v) {
    const r = await call("ss_recon_overview");
    const diffs = r.variants.filter((x) => x.differs), last = r.runs.find((x) => x.kind === "tiendanube_live"), lastI = r.runs.find((x) => x.kind === "internal");
    const list = onlyDiff ? diffs : r.variants;
    v.innerHTML = `<div class="head"><div><h1>Conciliación</h1><p>Supabase manda. Lo que Tiendanube tenga distinto se corrige hacia el maestro y queda registrado.</p></div>
        ${staff() ? `<div class="actions"><button class="btn gold" id="run">Conciliar ahora</button></div>` : ""}</div>
      <dl class="facts">${fact("Variantes revisadas", last?.checked ?? 0)}${fact("Diferencias ahora", diffs.length, diffs.length ? "bad" : "ok")}
        ${fact("Última lectura de Tiendanube", when(last?.finished_at))}${fact("Corregidas en esa lectura", last?.details?.drift?.length ?? 0)}
        ${fact("Sin mapeo", last?.details?.unmapped?.length ?? 0, last?.details?.unmapped?.length ? "bad" : "ok")}
        ${fact("Conciliación interna", lastI ? `${lastI.mismatches} diferencias` : "—", lastI?.mismatches ? "bad" : "ok")}
        ${fact("Eventos pendientes", r.pending_events, r.pending_events ? "warn" : "ok")}${fact("Líneas sin descontar", r.failed_lines, r.failed_lines ? "bad" : "ok")}</dl>
      <h2>Variantes</h2>
      <label class="check gap"><input type="checkbox" id="od" ${onlyDiff ? "checked" : ""}> Solo diferencias</label>
      ${list.length ? `<table class="rows"><thead><tr><th>Variante</th><th class="n">Maestro</th><th class="n">Reservado</th><th class="n">Vendido</th><th class="n">Debe publicar</th><th class="n">Tiendanube</th><th>Estado</th></tr></thead><tbody>
      ${list.map((x) => `<tr class="${x.differs ? "fail" : ""}"><td class="wide"><div class="main">${esc(x.product_name ?? "Variante " + x.variant_id)}</div><div class="sub">${esc(x.variant_label ?? `${x.style} · ${x.color} · ${x.size}`)}</div></td>
        <td class="n" data-l="Maestro">${num(x.quantity)}${x.stock_verified ? "" : `<div class="sub">sin contar</div>`}</td><td class="n" data-l="Reservado">${num(x.reserved)}</td><td class="n" data-l="Vendido">${num(x.sold)}</td>
        <td class="n" data-l="Debe publicar">${num(x.desired_stock)}</td><td class="n" data-l="Tiendanube">${x.tn_stock_live === null ? "—" : num(x.tn_stock_live)}</td>
        <td class="wide">${x.tn_stock_live === null ? `<span class="tag mute">Sin leer</span>` : x.differs ? `<span class="tag bad">Difiere</span>` : `<span class="tag ok">Coincide</span>`}</td></tr>`).join("")}</tbody></table>` : `<p class="empty">Sin diferencias.</p>`}
      <h2>Ejecuciones</h2>
      <table class="rows"><thead><tr><th>Fecha</th><th>Tipo</th><th class="n">Revisado</th><th class="n">Diferencias</th></tr></thead><tbody>
      ${r.runs.map((x) => `<tr><td class="wide">${esc(when(x.finished_at ?? x.started_at))}</td><td data-l="Tipo">${x.kind === "tiendanube_live" ? "Tiendanube" : "Interna"}</td><td class="n" data-l="Revisado">${num(x.checked)}</td><td class="n" data-l="Diferencias">${num(x.mismatches)}</td></tr>`).join("")}</tbody></table>`;
    $("#od").addEventListener("change", (e) => { onlyDiff = e.target.checked; route(); });
    $("#run")?.addEventListener("click", async (e) => {
      const b = e.target; b.disabled = true; b.textContent = "Conciliando…";
      try {
        const { data, error } = await db.functions.invoke("ss-admin", { body: { action: "reconcile" } });
        if (error) { let m = error.message; try { m = (await error.context.json()).error ?? m; } catch {} throw new Error(m); }
        toast(`Conciliación terminada: ${data.checked ?? 0} variantes, ${data.drift ?? 0} corregidas`);
        await loadDash(); route();
      } catch (err) { fail(err); b.disabled = false; b.textContent = "Conciliar ahora"; }
    });
  }

  /* ---------- Alertas ---------- */
  async function viewAlertas(v) {
    const a = await call("ss_panel_alerts");
    const G = [["critico", "Problemas críticos"], ["operativa", "Advertencias operativas"], ["comercial", "Pendientes comerciales"]];
    v.innerHTML = `<div class="head"><div><h1>Alertas</h1><p>Cada problema aparece una sola vez, con sus repeticiones contadas.</p></div></div>
      ${a.length ? G.map(([k, l]) => { const rows = a.filter((x) => x.class === k); return rows.length ? `<section class="alert-group"><h2>${l}</h2>${rows.map((x) => `<div class="alert ${k}"><div>${esc(x.subject)}<small>${esc(when(x.last_seen_at))}${x.occurrences > 1 ? ` · ${x.occurrences} veces` : ""}</small></div>${staff() && x.kind !== "stock_unverified" ? `<button class="btn small" data-res="${esc(x.id)}">Resolver</button>` : ""}</div>`).join("")}</section>` : ""; }).join("") : `<p class="empty">Sin alertas abiertas.</p>`}`;
    v.querySelectorAll("[data-res]").forEach((b) => b.addEventListener("click", () => {
      const dlg = $("#dlg");
      dlg.innerHTML = `<h2>Resolver alerta</h2><p>Si la causa sigue, la alerta vuelve a abrirse sola.</p><label class="f">Nota <textarea id="why" rows="2" maxlength="300"></textarea></label><div class="dlg-actions"><button class="btn" id="no">Cancelar</button><button class="btn gold" id="yes">Resolver</button></div>`;
      dlg.showModal(); $("#no").addEventListener("click", () => dlg.close());
      $("#yes").addEventListener("click", async () => { try { await call("ss_resolve_alert", { p_alert: Number(b.dataset.res), p_note: $("#why").value }); dlg.close(); await loadDash(); route(); } catch (e) { fail(e); } });
    }));
  }

  /* ---------- Usuarios ---------- */
  async function viewUsuarios(v) {
    const u = await call("ss_list_users");
    v.innerHTML = `<div class="head"><div><h1>Usuarios</h1><p>Las cuentas nuevas entran sin permisos. Cada cambio de rol queda auditado.</p></div></div>
      <form id="inv" class="invite" novalidate><label>Invitar por correo <input id="invMail" type="email" autocomplete="off" required></label><button class="btn" type="submit">Enviar invitación</button></form>
      <p class="fine gap">La persona invitada entra sin permisos. Asignale el rol acá cuando aparezca en la lista.</p>
      <table class="rows"><thead><tr><th>Correo</th><th>Último ingreso</th><th>Rol</th></tr></thead><tbody>
      ${u.map((x) => `<tr><td class="wide main">${esc(x.email)}</td><td data-l="Último ingreso">${esc(when(x.last_sign_in_at))}</td><td data-l="Rol"><select data-user="${esc(x.id)}" aria-label="Rol de ${esc(x.email)}">${Object.entries(ROLE).map(([k, l]) => `<option value="${k}" ${k === x.role ? "selected" : ""}>${l}</option>`).join("")}</select></td></tr>`).join("")}</tbody></table>`;
    $("#inv").addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = $("#invMail").value.trim();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { toast("Correo inválido", true); return; }
      try {
        const { error } = await db.functions.invoke("ss-admin", { body: { action: "invite", email } });
        if (error) { let m = error.message; try { m = (await error.context.json()).error ?? m; } catch {} throw new Error(m); }
        toast("Invitación enviada"); route();
      } catch (err) { fail(err); }
    });
    v.querySelectorAll("[data-user]").forEach((s) => s.addEventListener("change", async () => {
      try { await call("ss_set_user_role", { p_user: s.dataset.user, p_role: s.value }); toast("Rol actualizado"); } catch (e) { fail(e); route(); }
    }));
  }

  // Sesión inicial
  db.auth.getSession().then(({ data }) => onSession(data.session));
})();
