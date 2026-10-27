(function () {
  var path = window.location.pathname;
  if (!path.endsWith("/")) path += "/";

  // --- Tab pills: mark the current page's own tab active ---
  document.querySelectorAll("#docs-tabs .tab-pill").forEach(function (a) {
    var href = a.getAttribute("href");
    if (!href.endsWith("/")) href += "/";
    if (href === path) a.classList.add("active");
  });

  var article = document.querySelector("article.prose");
  if (!article) return;

  // --- RFC 2119 keyword coloring: the spec's own markdown already wraps
  // each keyword in *single-asterisk* emphasis (confirmed by reading the
  // rendered output directly -- every MUST/MAY/etc. is already inside an
  // <em>), so this only needs to re-skin those <em> tags, never scan plain
  // text nodes for keywords that were never marked up in the first place. ---
  var KW_RE = /^(MUST NOT|SHOULD NOT|SHALL NOT|MUST|SHOULD|SHALL|MAY|REQUIRED|RECOMMENDED|OPTIONAL)$/;
  function kwClass(word) {
    var first = word.split(" ")[0];
    if (first === "MUST" || first === "SHALL" || first === "REQUIRED") return "kw--must";
    if (first === "SHOULD" || first === "RECOMMENDED") return "kw--should";
    if (first === "MAY" || first === "OPTIONAL") return "kw--may";
    return null;
  }
  article.querySelectorAll("em").forEach(function (em) {
    var text = em.textContent.trim();
    if (!KW_RE.test(text)) return;
    var cls = kwClass(text);
    if (!cls) return;
    var span = document.createElement("span");
    span.className = "kw " + cls;
    span.textContent = em.textContent;
    em.replaceWith(span);
  });

  // --- Spec requirement rows: REQ-<id> list items -> the .req grid ---
  function reqTag(text) {
    if (/\bMUST\b/.test(text)) return { label: "MUST", cls: "req-tag--must" };
    if (/\bMAY\b/.test(text)) return { label: "MAY", cls: "req-tag--may" };
    return { label: "DEFINES", cls: "req-tag--defines" };
  }
  // A list item's first block is the <a id="req-..."> directly in a
  // "tight" markdown list (no blank lines / nested content among items),
  // or that same <a> wrapped in a <p> in a "loose" one -- confirmed live:
  // §5's own REQ-5-8 has a nested sub-list under it, which makes
  // CommonMark render that *whole* list loose, not just that one item, so
  // every REQ-5-x row silently failed this check and never transformed.
  function reqAnchorOf(li) {
    var first = li.firstElementChild;
    if (!first) return null;
    if (first.tagName === "A") return first;
    if (first.tagName === "P" && first.firstElementChild && first.firstElementChild.tagName === "A") return first.firstElementChild;
    return null;
  }
  article.querySelectorAll("ul").forEach(function (ul) {
    var items = Array.prototype.slice.call(ul.children).filter(function (c) { return c.tagName === "LI"; });
    if (items.length === 0) return;
    var allReq = items.every(function (li) {
      var a = reqAnchorOf(li);
      return a && /^req-/.test(a.id);
    });
    if (!allReq) return;
    var wrapper = document.createElement("div");
    wrapper.className = "req-list";
    items.forEach(function (li) {
      var anchor = reqAnchorOf(li);
      var id = anchor.id;
      var reqIdText = id.toUpperCase().replace("REQ-", "REQ-");
      var wrappingP = anchor.parentElement.tagName === "P" ? anchor.parentElement : null;
      anchor.remove();
      var strong = li.querySelector("strong");
      var label = strong ? strong.textContent.replace(/:$/, "") : reqIdText;
      if (strong) strong.remove();
      // Unwrap the now-anchor-and-strong-less <p> so its own text rejoins
      // li's direct content instead of staying nested -- a <p> is exactly
      // what this function's own new .req markup provides itself.
      if (wrappingP) {
        while (wrappingP.firstChild) wrappingP.parentElement.insertBefore(wrappingP.firstChild, wrappingP);
        wrappingP.remove();
      }
      // A "loose" list (one triggered into that mode by a sibling item's
      // own nested content, like REQ-5-8's sub-bullets) renders its markup
      // with a newline text node between <li> and its own <p> -- strips
      // leading whitespace along with the separator colon, not just the
      // colon alone, so that leftover newline doesn't survive into the body.
      var bodyHtml = li.innerHTML.replace(/^\s*:\s*/, "");
      var tag = reqTag(li.textContent);
      var row = document.createElement("div");
      row.className = "req";
      row.id = id;
      row.innerHTML =
        '<div class="req-id"><a href="#' + id + '">' + label + '</a><span class="req-tag ' + tag.cls + '">' + tag.label + "</span></div>" +
        '<div class="req-body"></div>';
      // A <p> wrapper (not a plain innerHTML assignment) for the inline
      // run only -- REQ-5-8's own nested sub-list means bodyHtml isn't
      // always pure inline content, and a block element like a <ul> can't
      // legally live inside a <p> (confirmed live: the browser's own
      // error-recovery otherwise splices it into a visually broken mess).
      row.querySelector(".req-body").innerHTML = "<p>" + bodyHtml + "</p>";
      row.querySelectorAll(".req-body p ul, .req-body p ol").forEach(function (nested) {
        var p = nested.closest("p");
        p.insertAdjacentElement("afterend", nested);
      });
      wrapper.appendChild(row);
    });
    ul.replaceWith(wrapper);
  });

  // --- Callouts: every blockquote becomes a .note; one whose own text
  // reads as the RFC 2119 / requirement-ID boilerplate (not just any
  // mention of a keyword in passing) gets the normative (sky) treatment
  // instead of the plain informative (butter) one. ---
  article.querySelectorAll("blockquote").forEach(function (bq) {
    var text = bq.textContent.trim();
    var normative = /^The key words\b/i.test(text);
    var div = document.createElement("div");
    div.className = normative ? "note note-normative" : "note";
    var icon = document.createElement("i");
    icon.className = normative ? "ph ph-scales" : "ph ph-info";
    div.appendChild(icon);
    var body = document.createElement("div");
    body.innerHTML = bq.innerHTML;
    div.appendChild(body);
    bq.replaceWith(div);
  });

  // --- Code blocks: wrap every <pre> with a toolbar + copy button ---
  article.querySelectorAll("pre").forEach(function (pre) {
    var code = pre.querySelector("code");
    var text = code ? code.textContent : pre.textContent;
    var lang = /^\s*[{[]/.test(text) ? "JSON" : /::?=|\*\d/.test(text) ? "ABNF" : "CODE";
    var block = document.createElement("div");
    block.className = "code-block";
    var bar = document.createElement("div");
    bar.className = "code-block-bar";
    var label = document.createElement("span");
    label.textContent = lang;
    var copyBtn = document.createElement("button");
    copyBtn.className = "code-copy-btn";
    copyBtn.innerHTML = '<i class="ph ph-copy"></i> Copy';
    copyBtn.addEventListener("click", function () {
      navigator.clipboard.writeText(text).catch(function () {});
      copyBtn.innerHTML = '<i class="ph ph-copy"></i> Copied';
      setTimeout(function () {
        copyBtn.innerHTML = '<i class="ph ph-copy"></i> Copy';
      }, 1500);
    });
    bar.appendChild(label);
    bar.appendChild(copyBtn);
    pre.replaceWith(block);
    block.appendChild(bar);
    block.appendChild(pre);
  });

  // --- "On this page" sidebar: nested two levels (H2 top, H3 indented),
  // same scroll-position-based active-tracking this session already
  // debugged for the flat version -- only the markup/level changed. ---
  var toc = document.getElementById("TableOfContents");
  var tocSidebar = document.querySelector(".toc-sidebar");
  var headings = article.querySelectorAll("h2, h3");
  var linkByHeadingId = {};
  if (headings.length >= 2 && toc) {
    var list = document.createElement("ul");
    list.className = "toc";
    headings.forEach(function (h) {
      if (!h.id) return;
      var li = document.createElement("li");
      if (h.tagName === "H3") li.className = "toc-sub";
      var a = document.createElement("a");
      a.href = "#" + h.id;
      a.textContent = h.textContent.replace(/#$/, "").trim();
      li.appendChild(a);
      list.appendChild(li);
      linkByHeadingId[h.id] = a;
    });
    toc.appendChild(list);

    var activeLink = null;
    function setActive(id) {
      var next = id ? linkByHeadingId[id] : null;
      if (next === activeLink) return;
      if (activeLink) activeLink.classList.remove("active");
      if (next) next.classList.add("active");
      activeLink = next || null;
    }
    var TRIGGER_LINE_PX = 120;
    var ticking = false;
    function updateActive() {
      ticking = false;
      var current = null;
      for (var i = 0; i < headings.length; i++) {
        if (headings[i].getBoundingClientRect().top <= TRIGGER_LINE_PX) current = headings[i].id;
        else break;
      }
      setActive(current || headings[0].id);
    }
    window.addEventListener(
      "scroll",
      function () {
        if (!ticking) {
          ticking = true;
          requestAnimationFrame(updateActive);
        }
      },
      { passive: true },
    );
    updateActive();
  } else if (tocSidebar) {
    tocSidebar.hidden = true;
  }

  // --- Mobile "on this page" accordion: collapsed by default, collapses
  // again once a heading is picked. Wide screens ignore this entirely
  // (the toggle button itself is hidden there, see site.css). ---
  var toggle = document.getElementById("toc-toggle");
  if (toggle && toc) {
    var open = false;
    function narrow() {
      return window.innerWidth < 720;
    }
    function setOpen(v) {
      open = v;
      toc.hidden = narrow() && !v;
      var icon = toggle.querySelector("i");
      if (icon) icon.className = v ? "ph ph-caret-up" : "ph ph-caret-down";
    }
    setOpen(false);
    toggle.addEventListener("click", function () {
      setOpen(!open);
    });
    toc.addEventListener("click", function (e) {
      if (e.target.tagName === "A" && narrow()) setOpen(false);
    });
    window.addEventListener("resize", function () {
      toc.hidden = narrow() && !open;
    });
  }
})();
