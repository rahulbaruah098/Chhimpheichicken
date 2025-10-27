// /static/js/alerts.js
(() => {
  // ===== Helpers =====
  const hasFocus = () => document.visibilityState === "visible";
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  // Prefer a page-provided <audio id="ding">; else use WebAudio beep
  const playBeep = (() => {
    let pageDing = null;
    const tryPageDing = () => {
      if (!pageDing) pageDing = document.getElementById("ding");
      if (pageDing) {
        try { pageDing.currentTime = 0; pageDing.play(); return true; } catch (_) {}
      }
      return false;
    };
    return () => {
      if (tryPageDing()) return;
      try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const o = ctx.createOscillator();
        const g = ctx.createGain();
        o.type = "sine";
        o.frequency.value = 880; // A5
        g.gain.value = 0.07;
        o.connect(g); g.connect(ctx.destination);
        o.start();
        setTimeout(() => { o.stop(); ctx.close(); }, 450);
      } catch (_) { /* ignore */ }
    };
  })();

  // Toast UI (lightweight)
  const ensureToastHost = () => {
    let el = document.getElementById("toast-host");
    if (!el) {
      el = document.createElement("div");
      el.id = "toast-host";
      el.style.position = "fixed";
      el.style.zIndex = "999999";
      el.style.right = "16px";
      el.style.top = "16px";
      el.style.display = "grid";
      el.style.gap = "10px";
      document.body.appendChild(el);
    }
    return el;
  };

  const toast = (msg) => {
    const host = ensureToastHost();
    const card = document.createElement("div");
    card.style.background = "#0f172a";
    card.style.color = "white";
    card.style.padding = "12px 14px";
    card.style.borderRadius = "10px";
    card.style.boxShadow = "0 10px 30px rgba(2,6,23,.25)";
    card.style.maxWidth = "360px";
    card.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, 'Helvetica Neue', Arial";
    card.textContent = msg;
    host.appendChild(card);
    requestAnimationFrame(() => {
      card.style.transition = "opacity .35s ease, transform .35s ease";
      card.style.opacity = "1";
      card.style.transform = "translateY(0)";
    });
    setTimeout(() => {
      card.style.opacity = "0";
      card.style.transform = "translateY(-6px)";
      setTimeout(() => host.removeChild(card), 400);
    }, 3500);
  };

  // Desktop notifications
  const desktopNotify = async (title, body) => {
    try {
      if (!("Notification" in window)) return;
      if (Notification.permission === "granted") {
        const n = new Notification(title, { body, icon: "/static/Images/logo.png" });
        n.onclick = () => {
          try {
            window.focus();
            n.close();
          } catch(_) {}
        };
      } else if (Notification.permission !== "denied") {
        const perm = await Notification.requestPermission();
        if (perm === "granted") {
          const n = new Notification(title, { body, icon: "/static/Images/logo.png" });
          n.onclick = () => {
            try {
              window.focus();
              n.close();
            } catch(_) {}
          };
        }
      }
    } catch (_) { /* ignore */ }
  };

  // Insert new order DOM if your template exposes an #orders-list container.
  // If it's a TBODY we insert <tr>; else we insert a card-like <div>.
  const insertOrderRowIfPossible = (role, item) => {
    const list = document.getElementById("orders-list");
    if (!list) return false;

    // Deduplicate
    if (list.querySelector(`[data-order-id="${item.order_id}"]`)) return true;

    const total = Number(item.total_payable ?? 0);
    const created = item.created_at ? new Date(item.created_at).toLocaleString() : "";

    // Table mode (tbody)
    if (list.tagName === "TBODY") {
      const tr = document.createElement("tr");
      tr.setAttribute("data-order-id", item.order_id);
      if (role === "store") {
        // Columns: # | Customer | Total | Status | Payment | Deliver To | Action
        tr.innerHTML = `
          <td>${item.order_id}</td>
          <td class="muted">—</td>
          <td>₹${isFinite(total) ? total.toFixed(2) : "—"}</td>
          <td>PLACED</td>
          <td>PENDING</td>
          <td class="muted">—</td>
          <td style="min-width:260px">
            <div class="muted" style="margin:6px 0">
              Total Payable: <strong>₹${isFinite(total) ? total.toFixed(2) : "—"}</strong>
            </div>
            <a class="btn-ghost" href="/orders/${item.order_id}">View items & track</a>
          </td>
        `;
      } else {
        // delivery role
        // Columns: # | Store | Customer | Total | Status | Address | Action | Quick Nav
        tr.innerHTML = `
          <td>${item.order_id}</td>
          <td class="muted">—</td>
          <td class="muted">—</td>
          <td>₹${isFinite(total) ? total.toFixed(2) : "—"}</td>
          <td>PLACED</td>
          <td class="muted">—</td>
          <td style="min-width:300px">
            <form method="post" action="/delivery/order/${item.order_id}/assign" style="display:inline-block;margin-right:6px">
              <button class="btn">Assign to me</button>
            </form>
          </td>
          <td class="muted">—</td>
        `;
      }
      // Prepend at top
      if (list.firstChild) list.insertBefore(tr, list.firstChild);
      else list.appendChild(tr);
      return true;
    }

    // Card mode (generic container)
    const row = document.createElement("div");
    row.setAttribute("data-order-id", item.order_id);
    row.style.border = "1px solid #e5e7eb";
    row.style.borderRadius = "10px";
    row.style.padding = "10px 12px";
    row.style.marginBottom = "10px";
    row.style.background = "#fff";
    row.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
        <div>
          <div style="font-weight:600">#${item.order_id}</div>
          <div style="font-size:12px;color:#6b7280">${created}</div>
        </div>
        <div style="font-size:14px;color:#0f172a">₹${isFinite(total) ? total.toFixed(2) : "—"}</div>
      </div>
    `;
    if (list.firstChild) list.insertBefore(row, list.firstChild);
    else list.appendChild(row);
    return true;
  };

  // ===== Poller =====
  async function startAlerts({ role }) {
    // Safety: role must be 'store' or 'delivery'
    if (!role || !/^(store|delivery)$/.test(role)) return;

    // initial window to not miss anything that happened just as we loaded
    let lastSince = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    let hadReload = false;

    while (true) {
      try {
        const url = role === "store" ? `/api/alerts/store?since=${encodeURIComponent(lastSince)}`
                                     : `/api/alerts/delivery?since=${encodeURIComponent(lastSince)}`;
        const res = await fetch(url, { credentials: "same-origin", cache: "no-store" });
        if (res.ok) {
          const data = await res.json();
          if (data && data.ok && Array.isArray(data.new) && data.new.length) {
            // Advance window using the newest created_at we see
            const newestISO = data.new
              .map(x => x.created_at)
              .filter(Boolean)
              .sort()
              .pop();

            // Bundle feedback
            const ids = data.new.map(x => `#${x.order_id}`).join(", ");
            const label = role === "store" ? "New order" : "New order available";
            const plural = data.new.length > 1 ? "s" : "";
            toast(`${label}${plural}: ${ids}`);
            playBeep();
            if (!hasFocus()) {
              desktopNotify("Chhimphei Chicken", `${label}${plural}: ${data.new.length}`);
            }

            // Try to insert rows; if we can’t, reload once to reflect server-rendered tables
            let insertedAtLeastOne = false;
            data.new.forEach(item => {
              if (insertOrderRowIfPossible(role, item)) insertedAtLeastOne = true;
            });
            if (!insertedAtLeastOne && !hadReload) {
              hadReload = true;
              // gentle delay so the toast shows before reload
              setTimeout(() => window.location.reload(), 700);
            }

            if (newestISO && newestISO > lastSince) lastSince = newestISO;
          }
        }
      } catch (e) {
        // Network hiccup—show a subtle toast only if tab is visible
        if (hasFocus()) toast("Reconnecting for alerts…");
      }

      // Backoff if hidden to save battery (visible: 5s, hidden: 12s)
      await sleep(hasFocus() ? 5000 : 12000);
    }
  }

  // Expose a tiny init; you’ll call this from templates
  window.initAlerts = startAlerts;

  // Optional: auto-start if a page sets data-role on <body>
  document.addEventListener("DOMContentLoaded", () => {
    const role = document.body?.dataset?.role;
    if (role) startAlerts({ role });
  });
})();
