// Guardianship diagram (landing hero) -- ported from the design handoff's
// own mockup logic (a React-like state machine + SMIL animations) into
// plain vanilla JS/DOM, since this static site has no component framework.
// Laura is the ward (clay core, center); guardians sit on a ring, evenly
// spread, each joined to the center by a spoke. See design_handoff_
// guardian_theme/README.md's own "Interactions and behavior" section for
// the full behavioral spec this ports.
(function () {
  var svg = document.getElementById("guardianship-svg");
  if (!svg) return;
  var SVG_NS = "http://www.w3.org/2000/svg";
  var CX = 220, CY = 200, RING_R = 150, NODE_R = 33;

  var COLOR_POOL = ["#1f62c4", "#6f8f58", "#f0a91a", "#6fa8ef", "#c9502c", "#526e40", "#7a4a2a", "#8f3218", "#45693a"];
  var NAME_POOL = ["troy", "carol", "adrianna", "anna", "tobias", "miriam", "jonah", "ruth", "eli"];

  function makeGuardian(poolIndex) {
    return { name: NAME_POOL[poolIndex % NAME_POOL.length], color: COLOR_POOL[poolIndex % COLOR_POOL.length], poolIndex: poolIndex, active: true, angle: 0 };
  }

  var state = {
    guardians: [makeGuardian(0), makeGuardian(1), makeGuardian(2)],
    nextPoolIndex: 3,
    busy: false,
    status: "idle",
    signed: {},
    reject: false,
    log: [],
    opCount: 2,
    timers: [],
  };

  function el(tag, attrs) {
    var e = document.createElementNS(SVG_NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  function active() {
    return state.guardians.filter(function (g) { return g.active; });
  }

  // Spreads active guardians evenly around the ring, in their own current order.
  function spread() {
    var act = active();
    act.forEach(function (g, i) { g.angle = (i * 360) / act.length; });
  }

  function at(ms, fn) {
    state.timers.push(setTimeout(fn, ms));
  }

  function push(type, sig, mark) {
    var n = mark === "✕" ? "----" : String(++state.opCount).padStart(4, "0");
    state.log.push({ n: n, type: type, sig: sig, mark: mark || "✓" });
    if (state.log.length > 5) state.log.shift();
    render();
  }

  function setButtonsDisabled(disabled) {
    document.querySelectorAll(".diagram-actions button").forEach(function (b) {
      b.disabled = disabled;
    });
  }

  function sign(names, then) {
    state.busy = true;
    state.status = "collecting signatures";
    state.signed = {};
    state.reject = false;
    render();
    names.forEach(function (nm, i) {
      at(450 * (i + 1), function () {
        state.signed[nm] = true;
        render();
      });
    });
    at(450 * names.length + 400, function () {
      state.status = "threshold met";
      render();
      then();
    });
  }

  function finish(ms) {
    at(ms, function () {
      state.busy = false;
      state.status = "idle";
      state.signed = {};
      state.reject = false;
      render();
    });
  }

  function run(type, pickIndices) {
    var act = active();
    var signers = pickIndices.map(function (i) { return act[i].name; });
    sign(signers, function () {
      push(type, "sig: " + signers.join(", ") + " · " + signers.length + "/" + act.length);
    });
    finish(450 * signers.length + 2200);
  }

  function transfer() {
    var act = active();
    var outgoing = act[0]; // oldest active guardian
    var signers = act.filter(function (g) { return g !== outgoing; }).map(function (g) { return g.name; });
    sign(signers, function () {
      var incoming = makeGuardian(state.nextPoolIndex++);
      state.guardians.push(incoming);
      spread();
      render();
      push("add_guardian", "incoming: " + incoming.name);
      at(1300, function () {
        outgoing.active = false;
        spread();
        render();
        push("remove_guardian", "outgoing: " + outgoing.name);
      });
    });
    finish(450 * signers.length + 400 + 3000);
  }

  function impersonate() {
    var g = active()[0];
    state.busy = true;
    state.status = "rejected";
    state.reject = true;
    state.signed = {};
    state.signed[g.name] = true;
    render();
    at(500, function () {
      push("update", "sig: " + g.name + ", as laura", "✕");
    });
    at(2200, function () {
      state.busy = false;
      state.status = "idle";
      state.reject = false;
      state.signed = {};
      render();
    });
  }

  // --- Idle animation: SMIL, only while nothing is busy ---
  var idleGroup = null;
  function buildIdle() {
    if (idleGroup) idleGroup.remove();
    if (state.busy) {
      idleGroup = null;
      return;
    }
    idleGroup = el("g", {});
    active().forEach(function (g, i) {
      var rad = (g.angle * Math.PI) / 180;
      var x = CX + RING_R * Math.sin(rad);
      var y = CY - RING_R * Math.cos(rad);
      var begin = i + "s";

      var pulse = el("circle", { cx: x, cy: y, r: NODE_R, fill: "none", stroke: g.color, "stroke-width": 2 });
      pulse.appendChild(el("animate", { attributeName: "r", values: "33;48", dur: "3s", begin: begin, repeatCount: "indefinite" }));
      pulse.appendChild(el("animate", { attributeName: "opacity", values: "0.8;0", dur: "3s", begin: begin, repeatCount: "indefinite" }));
      idleGroup.appendChild(pulse);

      var dot = el("circle", { r: 4, fill: g.color, opacity: 0 });
      dot.appendChild(el("animateMotion", { path: "M" + x + "," + y + " L" + CX + "," + CY, dur: "3s", begin: begin, repeatCount: "indefinite", keyPoints: "0;1;1", keyTimes: "0;0.55;1", calcMode: "linear" }));
      dot.appendChild(el("animate", { attributeName: "opacity", values: "0;1;1;0;0", keyTimes: "0;0.1;0.5;0.56;1", dur: "3s", begin: begin, repeatCount: "indefinite" }));
      idleGroup.appendChild(dot);
    });
    svg.appendChild(idleGroup);
  }

  // --- Full render: rebuilds the guardian ring + core + log + status ---
  var guardianLayer = null;
  var orbitRing = null;
  var coreCircle, rejectRingEl, laboraLabel;

  function buildStatic() {
    svg.innerHTML = "";
    orbitRing = el("circle", { cx: CX, cy: CY, r: 186, fill: "none", stroke: "var(--divider)", "stroke-width": 1, "stroke-dasharray": "2 7" });
    orbitRing.appendChild(el("animateTransform", { attributeName: "transform", type: "rotate", from: "0 " + CX + " " + CY, to: "360 " + CX + " " + CY, dur: "90s", repeatCount: "indefinite" }));
    svg.appendChild(orbitRing);

    guardianLayer = el("g", {});
    svg.appendChild(guardianLayer);

    coreCircle = el("circle", { cx: CX, cy: CY, r: 44, fill: "var(--clay)" });
    svg.appendChild(coreCircle);

    rejectRingEl = el("circle", { cx: CX, cy: CY, r: 58, fill: "none", stroke: "var(--clay)", "stroke-width": 2, "stroke-dasharray": "4 5", opacity: 0 });
    svg.appendChild(rejectRingEl);

    laboraLabel = el("text", { x: CX, y: CY + 5, "text-anchor": "middle", fill: "var(--cream)", style: "font:500 15px ui-monospace, Menlo, monospace;" });
    laboraLabel.textContent = "laura";
    svg.appendChild(laboraLabel);
  }

  function render() {
    guardianLayer.innerHTML = "";
    active().forEach(function (g) {
      var signedOn = !!state.signed[g.name];
      var wrap = el("g", { transform: "rotate(" + g.angle + " " + CX + " " + CY + ")" });
      var line = el("line", { x1: CX, y1: CY, x2: CX, y2: CY - RING_R, stroke: g.color, "stroke-width": 2, opacity: signedOn ? 1 : 0.35 });
      wrap.appendChild(line);
      var nodeWrap = el("g", { transform: "translate(" + CX + " " + (CY - RING_R) + ") rotate(" + -g.angle + ")" });
      var circle = el("circle", { r: NODE_R, fill: signedOn ? "color-mix(in srgb, " + g.color + " 35%, var(--paper))" : "var(--paper)", stroke: g.color, "stroke-width": 2.2 });
      nodeWrap.appendChild(circle);
      var label = el("text", { "text-anchor": "middle", y: 5, style: "font:500 13px ui-monospace, Menlo, monospace; fill: var(--ink-warm);" });
      label.textContent = g.name;
      nodeWrap.appendChild(label);
      wrap.appendChild(nodeWrap);
      guardianLayer.appendChild(wrap);
    });

    coreCircle.setAttribute("r", state.reject ? 40 : 44);
    rejectRingEl.setAttribute("opacity", state.reject ? 1 : 0);

    var statusEl = document.getElementById("diagram-status");
    if (statusEl) statusEl.textContent = state.status;

    var thresholdEl = document.getElementById("diagram-threshold");
    if (thresholdEl) thresholdEl.textContent = "ANY 2 OF " + active().length + " GUARDIANS";

    var logEl = document.getElementById("diagram-log-rows");
    if (logEl) {
      logEl.innerHTML = state.log
        .map(function (row) {
          return (
            '<div class="diagram-log-row"><span class="log-n">' + row.n + "</span><span class=\"log-type\">" + row.type +
            '</span><span class="log-sig">' + row.sig + '</span><span class="log-mark">' + row.mark + "</span></div>"
          );
        })
        .join("");
    }

    setButtonsDisabled(state.busy);
    buildIdle();
  }

  buildStatic();
  spread();
  render();

  document.querySelectorAll(".diagram-actions button").forEach(function (btn) {
    btn.addEventListener("click", function () {
      if (state.busy) return;
      var action = btn.getAttribute("data-action");
      if (action === "recover") run("recover", [0, 1]);
      else if (action === "revoke") run("revoke", [0, active().length - 1]);
      else if (action === "transfer") transfer();
      else if (action === "impersonate") impersonate();
    });
  });
})();
