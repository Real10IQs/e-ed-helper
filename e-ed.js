// ==UserScript==
// @name         E-ED Skipper by Real
// @namespace    http://tampermonkey.net/
// @version      8.1
// @description  Updated to new UI, fix various bug/error from heartbeat api
// @match        https://e-ed.e-tech.ac.th/*
// @grant        none
// ==/UserScript==

(function () {
  "use strict";

  // ==========================================
  // SECTION 1: CONSTANTS & GLOBAL STATE
  // ==========================================
  const STORAGE_KEY_AUTH = "EED_USER_AUTH_TOKEN";
  const STORAGE_KEY_XSRF = "EED_USER_XSRF_TOKEN";
  const AUTO_RUN_KEY = "EED_AUTO_RUN_ACTIVE";
  const TASKS_KEY = "EED_BACKGROUND_TASKS";
  const WIDGET_POS_KEY = "EED_WIDGET_POS";
  const WIDGET_MIN_KEY = "EED_WIDGET_MINIMIZED";
  const CLEAR_COMPLETED_DELAY_MS = 10000;

  let isTaskRunning = false;
  let sniffedHeartbeatPayload = null;
  let courseLessons = [];
  let lessonsLoaded = false;
  let lessonsPromise = null;

  let capturedRecId = null;
  let capturedOpenId = null;
  const capturedHeaders = {};

  let syncCountdownSec = 30;

  // ==========================================
  // SECTION 2: CREDENTIAL CAPTURE & NETWORK INTERCEPTORS
  // ==========================================
  function parseObjectForCredentials(obj) {
    if (!obj || typeof obj !== "object") return;
    if (Array.isArray(obj)) {
      obj.forEach(parseObjectForCredentials);
      return;
    }
    for (const key of Object.keys(obj)) {
      const val = obj[key];
      if (val === null || val === undefined) continue;

      const k = key.toLowerCase();
      if (
        (k === "recid" || k === "rec_id" || k === "tracking_id") &&
        !isNaN(val)
      ) {
        const num = Number(val);
        if (num > 1) capturedRecId = num;
      }
      if (
        (k === "openid" || k === "open_id") &&
        (typeof val === "string" || typeof val === "number")
      ) {
        const strVal = String(val).trim();
        if (strVal.length > 0) capturedOpenId = strVal;
      }
      if (typeof val === "object") {
        parseObjectForCredentials(val);
      }
    }
  }

  function captureHeadersFromConfig(headersObj) {
    if (!headersObj) return;
    const entries =
      headersObj instanceof Headers
        ? [...headersObj.entries()]
        : Object.entries(headersObj);
    for (const [k, v] of entries) {
      const key = k.toLowerCase();
      if (
        [
          "authorization",
          "x-csrf-token",
          "x-xsrf-token",
          "app-no",
          "app-time",
        ].includes(key)
      ) {
        capturedHeaders[key] = v;
      }
    }
  }

  const _origFetch = window.fetch;
  window.fetch = async function (...args) {
    const [resource, config] = args;
    const urlStr =
      typeof resource === "string" ? resource : resource?.url || "";

    if (config?.headers) captureHeadersFromConfig(config.headers);
    if (config?.body && typeof config.body === "string") {
      try {
        const payload = JSON.parse(config.body);
        parseObjectForCredentials(payload);
        if (urlStr.includes("/heartbeat")) {
          sniffedHeartbeatPayload = payload;
        }
      } catch (_) {}
    }

    const response = await _origFetch.apply(this, args);
    try {
      const clone = response.clone();
      const resData = await clone.json();
      parseObjectForCredentials(resData);
    } catch (_) {}
    return response;
  };

  const _xhrOpen = XMLHttpRequest.prototype.open;
  const _xhrSend = XMLHttpRequest.prototype.send;
  const _xhrSetHdr = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
    if (
      ["authorization", "x-csrf-token", "x-xsrf-token"].includes(
        k.toLowerCase(),
      )
    ) {
      capturedHeaders[k.toLowerCase()] = v;
    }
    if (k.toLowerCase() === "authorization") {
      saveTokens(v.replace(/^bearer\s+/i, "").trim(), getCookie("XSRF-TOKEN"));
    }
    return _xhrSetHdr.apply(this, arguments);
  };

  XMLHttpRequest.prototype.open = function (method, url) {
    this._eedUrl = url || "";
    return _xhrOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    if (body && typeof body === "string") {
      try {
        const payload = JSON.parse(body);
        parseObjectForCredentials(payload);
        if (this._eedUrl.includes("/heartbeat")) {
          sniffedHeartbeatPayload = payload;
        }
      } catch (_) {}
    }
    this.addEventListener("load", function () {
      try {
        parseObjectForCredentials(JSON.parse(this.responseText));
      } catch (_) {}
    });
    return _xhrSend.call(this, body);
  };

  // ==========================================
  // SECTION 3: AUTHENTICATION & TOKEN HELPERS
  // ==========================================
  function getCookie(name) {
    const v = ("; " + document.cookie).split("; " + name + "=");
    return v.length === 2
      ? decodeURIComponent(v.pop().split(";").shift())
      : null;
  }

  function getSavedAuth() {
    const t = localStorage.getItem(STORAGE_KEY_AUTH);
    return t
      ? t
          .replace(/^bearer\s+/i, "")
          .replace(/['"]/g, "")
          .trim()
      : null;
  }

  function saveTokens(auth, xsrf) {
    if (auth) localStorage.setItem(STORAGE_KEY_AUTH, auth);
    if (xsrf) localStorage.setItem(STORAGE_KEY_XSRF, xsrf);
  }

  function clearTokens() {
    localStorage.removeItem(STORAGE_KEY_AUTH);
    localStorage.removeItem(STORAGE_KEY_XSRF);
  }

  function getTokens() {
    const auth = getSavedAuth();
    const xsrf =
      localStorage.getItem(STORAGE_KEY_XSRF) || getCookie("XSRF-TOKEN");
    if (auth && xsrf) return { auth, xsrf };
    throw new Error(
      "No token yet. Please manually start the video for 1 second to register your session.",
    );
  }

  function getOpenIdFromToken(token) {
    try {
      if (!token) return null;
      const cleanToken = token
        .replace(/^bearer\s+/i, "")
        .replace(/['"]/g, "")
        .trim();
      const parts = cleanToken.split(".");
      if (parts.length < 2) return null;
      let base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      while (base64.length % 4) base64 += "=";
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split("")
          .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join(""),
      );
      const parsed = JSON.parse(jsonPayload);
      return parsed.sub ? Number(parsed.sub) : null;
    } catch (_) {
      return null;
    }
  }

  async function registerDocumentHeartbeat(topicId, tabLabel = "") {
    const exactLessonId = sniffedHeartbeatPayload?.lessonid || topicId;
    const exactRecId = sniffedHeartbeatPayload?.recid || capturedRecId;
    let tokens = {};
    try {
      tokens = getTokens();
    } catch (_) {}

    let docCompleted = false;
    let retryCount = 0;

    while (!docCompleted) {
      if (!sessionStorage.getItem(AUTO_RUN_KEY)) break;
      retryCount++;

      try {
        const reqHeaders = {
          accept: "application/json, text/plain, */*",
          "content-type": "application/json",
          authorization: `Bearer ${tokens.auth || ""}`,
          "x-xsrf-token": tokens.xsrf || "",
          "x-csrf-token":
            capturedHeaders["x-csrf-token"] ||
            document
              .querySelector('meta[name="csrf-token"]')
              ?.getAttribute("content") ||
            "",
          "app-time": String(Math.floor(Date.now() / 1000)),
        };

        const appNoHeader =
          capturedHeaders["app-no"] ||
          document
            .querySelector('meta[name="app-no"]')
            ?.getAttribute("content");
        if (appNoHeader) reqHeaders["app-no"] = appNoHeader;

        const hbRes = await _origFetch("https://e-ed.e-tech.ac.th/heartbeat", {
          method: "POST",
          headers: reqHeaders,
          body: JSON.stringify({
            lessonid: Number(exactLessonId),
            itemid: String(topicId),
            recid: Number(exactRecId || 0),
          }),
        });

        const hbData = await hbRes.json().catch(() => null);

        if (
          hbRes.status === 429 ||
          (hbData &&
            hbData.message &&
            hbData.message.includes("Too Many Attempts"))
        ) {
          setAutoBtnText(
            `Too Many Attempts | (Attempt #${retryCount})`,
          );
          await new Promise((r) => setTimeout(r, 5000));
          continue;
        }

        if (hbRes.ok && (hbData?.success || hbData?.item_complete === "Y")) {
          docCompleted = true;
          markItemCompletedInDOM(topicId);
        } else {
          await new Promise((r) => setTimeout(r, 1000));
          docCompleted = true;
        }
      } catch (_) {
        await new Promise((r) => setTimeout(r, 3000));
      }
    }
  }

  // ==========================================
  // SECTION 4: STORAGE & TASK STATE MANAGEMENT
  // ==========================================
  function getStoredTasks() {
    try {
      return JSON.parse(sessionStorage.getItem(TASKS_KEY) || "{}");
    } catch (_) {
      return {};
    }
  }

  function saveStoredTasks(tasks) {
    sessionStorage.setItem(TASKS_KEY, JSON.stringify(tasks));
  }

  function clearAllTasks() {
    sessionStorage.removeItem(TASKS_KEY);
    renderProgressionWidget();
  }

  // ==========================================
  // SECTION 5: UI COMPONENTS & PROGRESSION WIDGET
  // ==========================================
  function injectStyles() {
    const style = document.createElement("style");
    style.textContent = `
      .eed-btn {
          position: fixed; padding: 11px 22px; color: #fff; font-weight: 700;
          font-size: 14px; font-family: 'Segoe UI', system-ui, sans-serif;
          letter-spacing: 0.5px; border: none; border-radius: 12px; cursor: pointer;
          z-index: 9999; box-shadow: 0 6px 20px rgba(0,0,0,0.25), inset 0 1px 0 rgba(255,255,255,0.15);
          transition: transform 0.12s ease, box-shadow 0.12s ease, opacity 0.12s ease;
          backdrop-filter: blur(4px); user-select: none; bottom: 24px; right: 24px;
      }
      .eed-btn:hover { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
      .eed-btn:active { transform: scale(0.96); }
      .eed-btn-purple { background: linear-gradient(135deg, #9b59b6, #8e44ad); }
      .eed-btn-red    { background: linear-gradient(135deg, #e74c3c, #c0392b); }
      @keyframes eed-popin { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function getLessonTitleFromDOM(itemId) {
    try {
      if (!itemId) return null;
      const link = document.querySelector(
        `#sidebar a[href*="/${itemId}"], a[href*="/${itemId}"]`,
      );
      if (!link) return null;

      const itemSpan = link.querySelector("span");
      const itemTitle = itemSpan
        ? itemSpan.textContent.trim()
        : link.textContent.trim();

      const sidebarItem = link.closest(".sidebar-item");
      let unitTitle = "";
      if (sidebarItem) {
        const mainHeader = sidebarItem.querySelector(".menu-main");
        if (mainHeader) unitTitle = mainHeader.textContent.trim();
      }

      return unitTitle ? `${unitTitle} - ${itemTitle}` : itemTitle;
    } catch (_) {
      return null;
    }
  }

  function makeWidgetDraggable(elmnt, handle) {
    let pos1 = 0,
      pos2 = 0,
      pos3 = 0,
      pos4 = 0;
    handle.onmousedown = dragMouseDown;

    function dragMouseDown(e) {
      if (
        e.target.tagName === "BUTTON" ||
        e.target.classList.contains("no-drag")
      )
        return;
      e.preventDefault();
      pos3 = e.clientX;
      pos4 = e.clientY;
      document.onmouseup = closeDragElement;
      document.onmousemove = elementDrag;
    }

    function elementDrag(e) {
      e.preventDefault();
      pos1 = pos3 - e.clientX;
      pos2 = pos4 - e.clientY;
      pos3 = e.clientX;
      pos4 = e.clientY;
      const newTop = elmnt.offsetTop - pos2 + "px";
      const newLeft = elmnt.offsetLeft - pos1 + "px";
      elmnt.style.top = newTop;
      elmnt.style.left = newLeft;

      const savedPos = JSON.parse(
        sessionStorage.getItem(WIDGET_POS_KEY) || "{}",
      );
      sessionStorage.setItem(
        WIDGET_POS_KEY,
        JSON.stringify({
          ...savedPos,
          top: newTop,
          left: newLeft,
        }),
      );
    }

    function closeDragElement() {
      document.onmouseup = null;
      document.onmousemove = null;
    }
  }

  function renderProgressionWidget() {
    let widget = document.getElementById("eedProgressWidget");
    if (!widget) {
      widget = document.createElement("div");
      widget.id = "eedProgressWidget";
      widget.style.cssText = `
      position: fixed; top: 20px; left: 20px; width: 320px; min-width: 240px;
      display: flex; flex-direction: column;
      background: rgba(30, 30, 46, 0.95); color: #cdd6f4; font-family: 'Segoe UI', system-ui, sans-serif;
      font-size: 11px; z-index: 99999; border-radius: 12px; padding: 10px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1);
      backdrop-filter: blur(8px); box-sizing: border-box;
    `;

      const savedPos = JSON.parse(
        sessionStorage.getItem(WIDGET_POS_KEY) || "null",
      );
      if (savedPos) {
        widget.style.top = savedPos.top;
        widget.style.left = savedPos.left;
        if (savedPos.width) widget.style.width = savedPos.width;
        if (savedPos.height) widget.style.height = savedPos.height;
      }
      document.body.appendChild(widget);

      new ResizeObserver(() => {
        if (sessionStorage.getItem(WIDGET_MIN_KEY) !== "1") {
          const savedPos = JSON.parse(
            sessionStorage.getItem(WIDGET_POS_KEY) || "{}",
          );
          sessionStorage.setItem(
            WIDGET_POS_KEY,
            JSON.stringify({
              ...savedPos,
              width: widget.style.width,
              height: widget.style.height,
            }),
          );
        }
      }).observe(widget);
    }

    const tasks = getStoredTasks();
    const taskKeys = Object.keys(tasks);
    const isMinimized = sessionStorage.getItem(WIDGET_MIN_KEY) === "1";

    if (isMinimized) {
      widget.style.resize = "none";
      widget.style.height = "auto";
      widget.style.overflow = "hidden";
    } else {
      widget.style.resize = "both";
      widget.style.overflow = "hidden";
      const savedPos = JSON.parse(
        sessionStorage.getItem(WIDGET_POS_KEY) || "{}",
      );
      if (savedPos.height) {
        widget.style.height = savedPos.height;
      }
    }

    let html = `
    <div id="eedWidgetHeader" style="font-weight:bold; color:#a6e3a1; font-size:12px; display:flex; justify-content:space-between; align-items:center; cursor:move; user-select:none; flex-shrink:0; margin-bottom:${isMinimized ? "0" : "8px"};">
      <span>Video Progress (${taskKeys.length}) <span id="eedSyncTimer" style="font-size:10px; color:#89b4fa; margin-left:4px;">⏱ ${syncCountdownSec}s</span></span>
      <div style="display:flex; align-items:center; gap:4px;">
        <button id="eedClearBtn" class="no-drag" style="background:#e74c3c; border:none; color:#fff; font-weight:bold; font-size:10px; cursor:pointer; padding:2px 6px; border-radius:4px;" title="Clear All Queue">Clear All</button>
        <button id="eedMinBtn" class="no-drag" style="background:none; border:none; color:#a6adc8; font-weight:bold; font-size:14px; cursor:pointer; padding:0 4px;">${isMinimized ? "+" : "−"}</button>
      </div>
    </div>
    <div id="eedWidgetBody" style="display:${isMinimized ? "none" : "block"}; flex:1; min-height:0; overflow-y:auto;">
  `;

    if (taskKeys.length === 0) {
      html += `<div style="color:#a6adc8;">No active background video streams.</div>`;
    } else {
      taskKeys.forEach((id) => {
        const task = tasks[id];
        const isUnfinishable =
          task.status && task.status.includes("Unfinishable");
        const displayTitle =
          getLessonTitleFromDOM(id) || task.title || "Lesson " + id;
        html += `
        <div style="background:#181825; padding:6px 8px; border-radius:6px; margin-bottom:6px; border:1px solid ${isUnfinishable ? "#e74c3c" : "#313244"};">
          <div style="display:flex; justify-content:space-between; font-weight:600; color:#cdd6f4; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
            <span title="${displayTitle}">${displayTitle}</span>
            <span style="color:${isUnfinishable ? "#e74c3c" : task.percent >= 100 ? "#a6e3a1" : "#f9e2af"}">${task.percent}%</span>
          </div>
          <div style="background:#11111b; height:6px; border-radius:3px; overflow:hidden; margin-top:4px;">
            <div style="background:${isUnfinishable ? "#e74c3c" : task.percent >= 100 ? "#a6e3a1" : "#89b4fa"}; width:${Math.min(100, task.percent)}%; height:100%; transition:width 0.3s;"></div>
          </div>
          <div style="font-size:10px; color:#a6adc8; margin-top:3px; display:flex; justify-content:space-between;">
            <span>Status: <strong style="color:${isUnfinishable ? "#e74c3c" : task.percent >= 100 ? "#a6e3a1" : "#fab387"}">${task.status}</strong></span>
            <span>${task.viewTime || 0}s / ${task.fullTime || 0}s</span>
          </div>
        </div>
      `;
      });
    }

    html += `</div>`;
    widget.innerHTML = html;

    const header = document.getElementById("eedWidgetHeader");
    if (header) makeWidgetDraggable(widget, header);

    const minBtn = document.getElementById("eedMinBtn");
    if (minBtn) {
      minBtn.onclick = (e) => {
        e.stopPropagation();
        const minState = sessionStorage.getItem(WIDGET_MIN_KEY) === "1";
        sessionStorage.setItem(WIDGET_MIN_KEY, minState ? "0" : "1");
        renderProgressionWidget();
      };
    }

    const clearBtn = document.getElementById("eedClearBtn");
    if (clearBtn) {
      clearBtn.onclick = (e) => {
        e.stopPropagation();
        clearAllTasks();
      };
    }
  }

  function markItemCompletedInDOM(itemId) {
    try {
      const el = document.querySelector(`a[href*="${itemId}"]`);
      if (el) {
        el.style.opacity = "0.75";
        el.style.borderLeft = "4px solid #1db954";
      }
    } catch (_) {}
  }

  function showUnfinishablePopup(lessonTitle) {
    const overlay = document.createElement("div");
    overlay.innerHTML = `
      <div style="position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(0,0,0,0.7); backdrop-filter:blur(6px); z-index:100000; display:flex; justify-content:center; align-items:center;">
        <div style="background:#fff; padding:35px; border-radius:20px; text-align:center; box-shadow:0 15px 35px rgba(0,0,0,0.4); max-width:440px; animation: eed-popin 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);">
          <h2 style="margin:0 0 12px; color:#e74c3c; font-family:'Segoe UI', sans-serif; font-size:22px; font-weight:bold;">Course Unable to Finish Legitimately</h2>
          <p style="color:#555; font-size:14px; margin-bottom:20px; line-height:1.5;">The video in lesson <strong>"${lessonTitle || "Current Topic"}"</strong> is missing, broken, or unavailable on the server. Automatic progress cannot continue.</p>
          <button id="closeEedUnfinishBtn" style="background:linear-gradient(135deg, #e74c3c, #c0392b); color:#fff; border:none; padding:12px 30px; border-radius:10px; font-size:15px; font-weight:700; cursor:pointer; box-shadow:0 4px 10px rgba(231, 76, 60, 0.3);">Dismiss</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    const closeBtn = document.getElementById("closeEedUnfinishBtn");
    closeBtn.onclick = () => overlay.remove();
  }

  function setAutoBtnText(text) {
    const btn = document.getElementById("eedAutoBtn");
    if (btn) btn.textContent = text;
  }

  function updateAutoBtnUI() {
    const btn = document.getElementById("eedAutoBtn");
    if (!btn) return;
    const isAuto = sessionStorage.getItem(AUTO_RUN_KEY);
    btn.className = "eed-btn " + (isAuto ? "eed-btn-red" : "eed-btn-purple");
    btn.textContent = isAuto ? "Stop Auto-Run" : "Auto-Complete Course";
  }

  function addAutoButton() {
    if (document.getElementById("eedAutoBtn")) return;
    const btn = document.createElement("button");
    btn.id = "eedAutoBtn";
    document.body.appendChild(btn);
    updateAutoBtnUI();
    btn.onclick = () => {
      if (sessionStorage.getItem(AUTO_RUN_KEY)) {
        sessionStorage.removeItem(AUTO_RUN_KEY);
        isTaskRunning = false;
        updateAutoBtnUI();
      } else {
        sessionStorage.setItem(AUTO_RUN_KEY, "1");
        updateAutoBtnUI();
        executeCurrentTask();
      }
    };
  }

  function showCompletionPopup() {
    const overlay = document.createElement("div");
    overlay.innerHTML = `
      <div style="position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(0,0,0,0.6); backdrop-filter:blur(5px); z-index:100000; display:flex; justify-content:center; align-items:center;">
          <div style="background:#fff; padding:40px; border-radius:20px; text-align:center; box-shadow:0 15px 35px rgba(0,0,0,0.3); max-width:400px; animation: eed-popin 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);">
              <h2 style="margin:0 0 12px; color:#1db954; font-family:'Segoe UI', sans-serif; font-size:26px;">Course Completed!</h2>
              <button id="closeEedPopupBtn" style="background:linear-gradient(135deg, #1db954, #17a349); color:#fff; border:none; padding:12px 30px; border-radius:10px; font-size:16px; font-weight:700; cursor:pointer; box-shadow:0 4px 10px rgba(29, 185, 84, 0.3); transition: transform 0.1s;">Okay</button>
          </div>
      </div>
    `;
    document.body.appendChild(overlay);
    const closeBtn = document.getElementById("closeEedPopupBtn");
    closeBtn.onmousedown = () => (closeBtn.style.transform = "scale(0.95)");
    closeBtn.onmouseup = () => (closeBtn.style.transform = "scale(1)");
    closeBtn.onclick = () => overlay.remove();
  }

  // ==========================================
  // SECTION 6: BACKGROUND PULSE ENGINE
  // ==========================================
  function startGlobalBackgroundPulseLoop() {
    setInterval(() => {
      const tasks = getStoredTasks();
      const hasActiveVideos = Object.values(tasks).some(
        (t) =>
          t &&
          t.percent < 100 &&
          t.status !== "Completed" &&
          !t.status.includes("Unfinishable"),
      );

      const syncEl = document.getElementById("eedSyncTimer");
      if (!hasActiveVideos) {
        if (syncEl) syncEl.textContent = "⏱ Standby";
        syncCountdownSec = 30;
        return;
      }

      syncCountdownSec--;
      if (syncCountdownSec < 0) syncCountdownSec = 30;
      if (syncEl) syncEl.textContent = `⏱ ${syncCountdownSec}s`;
    }, 1000);

    setInterval(async () => {
      const tasks = getStoredTasks();
      const taskKeys = Object.keys(tasks);
      if (taskKeys.length === 0) return;

      const activeTasks = Object.values(tasks).filter(
        (t) =>
          t &&
          t.percent < 100 &&
          t.status !== "Completed" &&
          !t.status.includes("Unfinishable"),
      );

      if (activeTasks.length === 0) return;

      syncCountdownSec = 30;

      let tokens = {};
      try {
        tokens = getTokens();
      } catch (_) {}

      if (!tokens.auth) return;

      const now = Date.now();
      let modified = false;

      for (const id of taskKeys) {
        const task = tasks[id];
        if (
          task.percent >= 100 &&
          task.completedAt &&
          now - task.completedAt >= CLEAR_COMPLETED_DELAY_MS
        ) {
          delete tasks[id];
          modified = true;
        }
      }

      if (modified) {
        saveStoredTasks(tasks);
        renderProgressionWidget();
      }

      const remainingKeys = Object.keys(tasks);

      for (const id of remainingKeys) {
        const task = tasks[id];
        if (
          task.percent >= 100 ||
          task.status === "Completed" ||
          task.status.includes("Unfinishable")
        )
          continue;

        const targetLessonId =
          task.lessonid || sniffedHeartbeatPayload?.lessonid || id;
        if (!targetLessonId || isNaN(Number(targetLessonId))) {
          task.status = "Skipped (Bad Lesson ID)";
          tasks[id] = task;
          continue;
        }

        try {
          const reqHeaders = {
            accept: "application/json, text/plain, */*",
            "content-type": "application/json",
            authorization: `Bearer ${tokens.auth}`,
            "x-xsrf-token": tokens.xsrf,
            "x-csrf-token":
              capturedHeaders["x-csrf-token"] ||
              document
                .querySelector('meta[name="csrf-token"]')
                ?.getAttribute("content") ||
              "",
            "app-time": String(Math.floor(Date.now() / 1000)),
          };

          const appNoHeader =
            capturedHeaders["app-no"] ||
            document
              .querySelector('meta[name="app-no"]')
              ?.getAttribute("content");
          if (appNoHeader) reqHeaders["app-no"] = appNoHeader;

          const hbRes = await _origFetch(
            "https://e-ed.e-tech.ac.th/heartbeat",
            {
              method: "POST",
              headers: reqHeaders,
              body: JSON.stringify({
                lessonid: Number(targetLessonId),
                itemid: String(id),
                recid: Number(task.recid),
              }),
            },
          );

          if (hbRes.status === 429) {
            task.status = "Rate Limited (429)";
            tasks[id] = task;
            saveStoredTasks(tasks);
            renderProgressionWidget();
            await new Promise((r) => setTimeout(r, 8000));
            continue;
          }

          const hbData = await hbRes.json().catch(() => null);
          if (hbData && hbData.success) {
            task.percent = hbData.percent ?? task.percent;
            task.viewTime = hbData.view_time ?? task.viewTime;
            task.fullTime = hbData.full_time ?? task.fullTime;
            task.status = "Pulsing API...";

            if (task.percent >= 100 || hbData.item_complete === "Y") {
              task.percent = 100;
              task.status = "Completed";
              if (!task.completedAt) task.completedAt = Date.now();
              markItemCompletedInDOM(id);

              await _origFetch(
                "https://e-ed.e-tech.ac.th/api/Stop-TopicTracking",
                {
                  method: "POST",
                  headers: reqHeaders,
                  body: JSON.stringify({
                    recid: Number(task.recid),
                    itemid: String(id),
                    courseid: Number(task.subjectId),
                    openid: Number(task.openid),
                    lessonid: Number(targetLessonId),
                    percent: 100,
                    status: "completed",
                  }),
                },
              ).catch(() => {});
            }
          } else if (hbData && hbData.success === false) {
            task.status = "Unfinishable Error";
          }
        } catch (_) {
          task.status = "Error";
        }

        tasks[id] = task;

        await new Promise((r) => setTimeout(r, 2000));
      }

      saveStoredTasks(tasks);
      renderProgressionWidget();
    }, 30000);
  }

  // ==========================================
  // SECTION 7: DOM HELPERS & QUIZ UTILITIES
  // ==========================================
  function getSubjectId() {
    let m = location.href.match(/subject\/(\d+)/);
    if (m) return m[1];
    const link = document.querySelector('a[href*="/subject/"]');
    if (link) {
      m = link.getAttribute("href").match(/subject\/(\d+)/);
      if (m) return m[1];
    }
    return null;
  }

  function getCurrentLessonIdFromUrl() {
    const match = location.href.match(/(?:topic|quiz)\/(\d+)/);
    return match ? match[1] : null;
  }

  function hasDocumentContent() {
    return !!(
      document.querySelector("#vuePdfApp") ||
      document.querySelector(".vue-pdf") ||
      document.querySelector(".tempnail img") ||
      document.querySelector(".card-body img") ||
      document.querySelector("iframe[src*='.pdf']") ||
      document.querySelector("iframe[src*='officeapps.live.com']") ||
      document.querySelector("iframe[src*='/Document/']") ||
      document.querySelector('a[href*="/Document/CourseId/"]') ||
      document.querySelector('a[href*=".docx"]')
    );
  }

  function normalizeText(html) {
    if (!html) return "";
    return new DOMParser()
      .parseFromString(html, "text/html")
      .body.textContent.trim()
      .replace(/\s+/g, " ");
  }

  function triggerInputSelection(choiceElem) {
    if (!choiceElem) return false;
    const itemContainer = choiceElem.closest(".option-item") || choiceElem;
    itemContainer.style.border = "2px solid #1db954";
    itemContainer.style.borderRadius = "6px";
    itemContainer.click();
    return true;
  }

  function selectChoiceInDOM(targetText, choiceIndex = null) {
    let clicked = false;
    const choiceElems = [
      ...document.querySelectorAll(".options .option-item, .option-text"),
    ];

    if (targetText && choiceElems.length > 0) {
      for (const choiceElem of choiceElems) {
        if (normalizeText(choiceElem.innerHTML) === targetText) {
          clicked = triggerInputSelection(choiceElem);
          if (clicked) break;
        }
      }
    }

    if (!clicked && choiceIndex !== null && choiceIndex >= 0) {
      const items = document.querySelectorAll(".options .option-item");
      if (items[choiceIndex]) {
        clicked = triggerInputSelection(items[choiceIndex]);
      }
    }
    return clicked;
  }

  function smartClickNext(maxWait = 600) {
    return new Promise((resolve) => {
      const tryFind = () => {
        const found = [
          ...document.querySelectorAll(
            "button:not([disabled]):not(#eedAutoBtn)",
          ),
        ].find((b) =>
          /next|ถัดไป|ต่อไป/i.test(b.innerText || b.textContent || ""),
        );
        if (found) {
          found.click();
          return true;
        }
        return false;
      };
      if (tryFind()) return resolve(true);
      const start = Date.now();
      const iv = setInterval(() => {
        if (tryFind()) {
          clearInterval(iv);
          resolve(true);
        } else if (Date.now() - start >= maxWait) {
          clearInterval(iv);
          resolve(false);
        }
      }, 15);
    });
  }

  function clickMatchingButton(regex, maxWait = 4000) {
    return new Promise((resolve) => {
      const start = Date.now();
      const iv = setInterval(() => {
        const btns = [...document.querySelectorAll("button:not(#eedAutoBtn)")];
        const target = btns.find((b) => {
          const text = (b.innerText || b.textContent || "").trim();
          return regex.test(text) && !b.disabled;
        });

        if (target) {
          target.click();
          target.dispatchEvent(new Event("click", { bubbles: true }));
          clearInterval(iv);
          resolve(true);
        } else if (Date.now() - start >= maxWait) {
          clearInterval(iv);
          resolve(false);
        }
      }, 50);
    });
  }

  async function waitAndConfirmModal() {
    await clickMatchingButton(/confirm|ยืนยัน|ส่ง|submit/i, 3000);
    await new Promise((r) => setTimeout(r, 200));

    await clickMatchingButton(/yes|ใช่/i, 5000);
    await new Promise((r) => setTimeout(r, 600));

    const okayRegex = /okay|ตกลง|ok/i;
    const start = Date.now();
    while (Date.now() - start < 8000) {
      const clicked = await clickMatchingButton(okayRegex, 500);
      if (clicked) break;
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  function getChoiceDbId(c) {
    return Number(c.id ?? c.choiceid ?? c.choice_id ?? c.id_choice ?? c.no);
  }

  function extractScorePercent(res) {
    if (!res || typeof res !== "object") return null;
    const t =
      res.data && typeof res.data === "object" ? { ...res, ...res.data } : res;

    let pct = t.percent ?? t.percentage ?? t.score_percent;
    if (pct !== undefined && pct !== null && !isNaN(pct)) return Number(pct);

    const pts = t.point ?? t.score ?? t.points ?? t.user_score;
    const tot =
      t.total ?? t.max_score ?? t.full_score ?? t.total_score ?? t.max_point;

    if (pts !== undefined && pts !== null && tot) {
      return Math.round((Number(pts) / Number(tot)) * 100);
    }

    if (t.score !== undefined && t.score !== null && !isNaN(t.score)) {
      return Number(t.score);
    }

    return null;
  }

  async function answerAllQuestionsInDOM(quizData, answersMap = null) {
    setAutoBtnText(
      answersMap ? "Replaying answers..." : "Answering questions...",
    );

    let pageCount = 0;
    const maxPages = quizData.length + 5;
    let lastQText = "";

    while (pageCount < maxPages) {
      if (!sessionStorage.getItem(AUTO_RUN_KEY)) return;
      pageCount++;

      let qElem = null;
      let currentQText = "";
      let attempts = 0;

      while (attempts < 15) {
        qElem = document.querySelector("main .question-text, .question-text");
        if (qElem) {
          currentQText = normalizeText(qElem.innerHTML);
          if (currentQText && currentQText !== lastQText) break;
        }
        await new Promise((r) => setTimeout(r, 20));
        attempts++;
      }

      if (!qElem || !currentQText || currentQText === lastQText) {
        break;
      }

      if (qElem && currentQText) {
        lastQText = currentQText;
        const qData = quizData.find(
          (q) =>
            normalizeText(
              q.question || q.title || q.quiz_title || q.item_title || "",
            ) === currentQText,
        );

        if (qData) {
          const qId = Number(qData.quizid || qData.id || qData.itemid);
          const choices =
            qData.choices || qData.options || qData.choices_show_answer || [];

          let targetChoiceDbId = answersMap ? answersMap[qId] : null;
          let choiceIdx = -1;

          if (targetChoiceDbId !== null && targetChoiceDbId !== undefined) {
            choiceIdx = choices.findIndex(
              (c) => getChoiceDbId(c) === targetChoiceDbId,
            );
          } else if (choices.length > 0) {
            choiceIdx = 0;
          }

          if (choiceIdx >= 0 && choices[choiceIdx]) {
            const targetChoiceObj = choices[choiceIdx];
            const choiceText = normalizeText(
              targetChoiceObj.choice_text ||
                targetChoiceObj.title ||
                targetChoiceObj.name ||
                targetChoiceObj.choice ||
                "",
            );
            selectChoiceInDOM(choiceText, choiceIdx);
          }
        }
      }

      await new Promise((r) => setTimeout(r, 30));

      const nextClicked = await smartClickNext(300);
      if (!nextClicked) {
        break;
      }

      await new Promise((r) => setTimeout(r, 50));
    }

    setAutoBtnText("Submitting in DOM...");
    await waitAndConfirmModal();
  }

  // ==========================================
  // SECTION 8: COURSE NAVIGATION & LESSON AUTOMATION
  // ==========================================
  function mapLessons(apiData, subjectId) {
    const lessons = [];
    if (!Array.isArray(apiData)) return lessons;

    apiData.forEach((section) => {
      if (section && Array.isArray(section.child)) {
        section.child.forEach((item) => {
          let targetUrl =
            item.item_type === "Q"
              ? "/subject/" + subjectId + "/quiz/" + item.itemid
              : "/subject/" + subjectId + "/topic/" + item.itemid + "/lesson";
          lessons.push({
            id: String(item.itemid),
            title: item.title,
            type: item.item_type,
            url: targetUrl,
          });
        });
      }
    });
    return lessons;
  }

  async function fetchCourseLessons(subjectId) {
    if (!subjectId) return [];
    if (lessonsLoaded && courseLessons.length > 0) return courseLessons;
    if (lessonsPromise) return lessonsPromise;

    lessonsPromise = (async () => {
      try {
        const tokens = getTokens();
        const recid = Math.floor(Math.random() * 2000000) + 1;
        const res = await fetch(
          "https://e-ed.e-tech.ac.th/api/course/" +
            subjectId +
            "/v2Items?recid=" +
            recid,
          {
            headers: {
              authorization: `Bearer ${tokens.auth}`,
              "x-xsrf-token": tokens.xsrf,
            },
          },
        );
        if (!res.ok) throw new Error("API error");
        courseLessons = mapLessons(await res.json(), subjectId);
        lessonsLoaded = true;
        return courseLessons;
      } catch (_) {
        return [];
      }
    })();
    return lessonsPromise;
  }

  async function goToNextLesson(currentId) {
    const subjectId = getSubjectId();
    if (!subjectId) return location.reload();
    try {
      const allItems = await fetchCourseLessons(subjectId);
      const index = allItems.findIndex((l) => l.id === String(currentId));
      if (index >= 0 && index + 1 < allItems.length) {
        const next = allItems[index + 1];
        const urlPath = new URL(next.url, location.origin).pathname;
        const link = document.querySelector(
          'a[href$="' + urlPath + '"], a[href*="' + urlPath + '"]',
        );
        if (link) {
          link.click();
          return;
        }
        location.href = next.url;
      } else if (index === allItems.length - 1) {
        sessionStorage.removeItem(AUTO_RUN_KEY);
        updateAutoBtnUI();
        showCompletionPopup();
      } else {
        location.reload();
      }
    } catch (_) {
      location.reload();
    }
  }

  async function waitForContentReady() {
    await new Promise((r) => setTimeout(r, 400));
    const maxTime = Date.now() + 15000;
    while (Date.now() < maxTime) {
      if (location.pathname.includes("/lesson")) {
        const hasVideo = !!(
          document.querySelector("iframe[src*='youtube']") ||
          document.querySelector(".lesson-youtube-block") ||
          document.querySelector("iframe#vue-youtube-iframe-1")
        );
        if (hasVideo || hasDocumentContent()) return true;
      }
      if (
        location.pathname.includes("/quiz/") &&
        document.querySelector("main .question-text, .question-text")
      ) {
        return true;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    return false;
  }

  async function performSkipVideoForCurrentTab() {
    const topicId = getCurrentLessonIdFromUrl();
    const subjectId = getSubjectId();

    let tokens = {};
    try {
      tokens = getTokens();
    } catch (_) {}

    const title =
      getLessonTitleFromDOM(topicId) ||
      document.title.replace(/[^a-zA-Z0-9ก-๙\s]/g, "").trim() ||
      "Video Lesson " + topicId;

    const ytIframe =
      document.querySelector("iframe[src*='youtube']") ||
      document.querySelector(".lesson-youtube-block iframe");

    if (!ytIframe) {
      const tasks = getStoredTasks();
      tasks[topicId] = {
        id: String(topicId),
        title: title,
        percent: 0,
        viewTime: 0,
        fullTime: 0,
        status: "Unfinishable (Missing Video)",
      };
      saveStoredTasks(tasks);
      renderProgressionWidget();

      sessionStorage.removeItem(AUTO_RUN_KEY);
      updateAutoBtnUI();
      isTaskRunning = false;

      showUnfinishablePopup(title);
      return false;
    }

    setAutoBtnText("Auto: Forcing system session intercept...");

    let waitAttempts = 0;
    while (
      (!sniffedHeartbeatPayload || !capturedHeaders["app-no"]) &&
      waitAttempts < 30
    ) {
      if (!sessionStorage.getItem(AUTO_RUN_KEY)) return false;

      if (ytIframe && ytIframe.contentWindow && waitAttempts % 4 === 0) {
        try {
          ytIframe.contentWindow.postMessage(
            JSON.stringify({ event: "command", func: "mute", args: [] }),
            "*",
          );
          ytIframe.contentWindow.postMessage(
            JSON.stringify({ event: "command", func: "playVideo", args: [] }),
            "*",
          );
          setTimeout(() => {
            try {
              ytIframe.contentWindow.postMessage(
                JSON.stringify({
                  event: "command",
                  func: "pauseVideo",
                  args: [],
                }),
                "*",
              );
            } catch (e) {}
          }, 300);
        } catch (e) {}
      }

      await new Promise((r) => setTimeout(r, 250));
      waitAttempts++;
    }

    const exactLessonId = sniffedHeartbeatPayload?.lessonid;
    const exactRecId = sniffedHeartbeatPayload?.recid;
    const appNo =
      capturedHeaders["app-no"] ||
      document.querySelector('meta[name="app-no"]')?.getAttribute("content");
    const openid =
      capturedOpenId || getOpenIdFromToken(tokens.auth) || "137689";

    if (!exactLessonId || !appNo || !exactRecId) {
      alert(
        "Could not intercept the real lesson ID. Please ensure the video is playable.",
      );
      sessionStorage.removeItem(AUTO_RUN_KEY);
      updateAutoBtnUI();
      isTaskRunning = false;
      return false;
    }

    const reqHeaders = {
      accept: "application/json, text/plain, */*",
      "content-type": "application/json",
      authorization: `Bearer ${tokens.auth}`,
      "x-xsrf-token": tokens.xsrf,
      "x-csrf-token":
        capturedHeaders["x-csrf-token"] ||
        document
          .querySelector('meta[name="csrf-token"]')
          ?.getAttribute("content") ||
        "",
      "app-time": String(Math.floor(Date.now() / 1000)),
      "app-no": appNo,
    };

    const tasks = getStoredTasks();
    tasks[topicId] = {
      id: String(topicId),
      lessonid: Number(exactLessonId),
      title: title,
      recid: Number(exactRecId),
      openid: String(openid),
      subjectId: Number(subjectId),
      percent: 0,
      viewTime: 0,
      fullTime: 0,
      status: "Verifying Progress...",
    };
    saveStoredTasks(tasks);
    renderProgressionWidget();

    let progressReached = false;
    let retries = 0;

    while (!progressReached) {
      if (!sessionStorage.getItem(AUTO_RUN_KEY)) {
        isTaskRunning = false;
        return false;
      }

      retries++;
      setAutoBtnText(`Auto: Registering video (Attempt #${retries})...`);

      try {
        reqHeaders["app-time"] = String(Math.floor(Date.now() / 1000));

        const hbRes = await _origFetch("https://e-ed.e-tech.ac.th/heartbeat", {
          method: "POST",
          headers: reqHeaders,
          body: JSON.stringify({
            lessonid: Number(exactLessonId),
            itemid: String(topicId),
            recid: Number(exactRecId),
          }),
        });

        const hbData = await hbRes.json().catch(() => null);
        if (hbData && hbData.success) {
          const vTime = Number(hbData.view_time || 0);
          const percent = Number(hbData.percent || 0);

          tasks[topicId].viewTime = vTime;
          tasks[topicId].percent = percent;
          tasks[topicId].fullTime = Number(hbData.full_time || 0);
          tasks[topicId].status = "Background Active";
          saveStoredTasks(tasks);
          renderProgressionWidget();

          if (vTime >= 1 || percent > 0 || hbData.item_complete === "Y") {
            progressReached = true;
            break;
          }
        }
      } catch (_) {}

      const retryDelayMs = Math.floor(Math.random() * 5000) + 5000;
      await new Promise((r) => setTimeout(r, retryDelayMs));
    }

    return true;
  }

  async function processAllLessonSubTabs() {
    const topicId = getCurrentLessonIdFromUrl();
    const getSubTabs = () => [
      ...document.querySelectorAll(
        ".lesson-tabs button.nav-link, .nav-tabs button.nav-link",
      ),
    ];
    let subTabs = getSubTabs();

    if (subTabs.length <= 1) {
      const hasVideos = !!(
        document.querySelector("iframe[src*='youtube']") ||
        document.querySelector(".lesson-youtube-block")
      );
      if (!hasVideos && hasDocumentContent()) {
        setAutoBtnText("Auto: Registering document...");
        await registerDocumentHeartbeat(topicId, "Auto:");
        setAutoBtnText("Auto: Document viewed.");
        await new Promise((r) => setTimeout(r, 300));
      } else {
        await performSkipVideoForCurrentTab();
      }
    } else {
      for (let i = 0; i < subTabs.length; i++) {
        if (!sessionStorage.getItem(AUTO_RUN_KEY)) return;

        subTabs = getSubTabs();
        const tab = subTabs[i];
        if (!tab) continue;

        setAutoBtnText(`Auto: Subtab ${i + 1}/${subTabs.length}`);

        if (!tab.classList.contains("active")) {
          tab.click();
          await new Promise((r) => setTimeout(r, 800));
        }

        await waitForContentReady();

        const hasVideos = !!(
          document.querySelector("iframe[src*='youtube']") ||
          document.querySelector(".lesson-youtube-block")
        );
        if (hasVideos) {
          const success = await performSkipVideoForCurrentTab();
          if (!success) return;
        } else {
          setAutoBtnText(
            `Auto: Registering document (Subtab ${i + 1}/${subTabs.length})...`,
          );
          await registerDocumentHeartbeat(topicId, `Auto: Subtab ${i + 1}`);
          setAutoBtnText(`Auto: Subtab ${i + 1} Document viewed.`);
          await new Promise((r) => setTimeout(r, 400));
        }
      }
    }

    setAutoBtnText("Auto: All subtabs completed! Moving to next topic...");
    await new Promise((r) => setTimeout(r, 300));
    isTaskRunning = false;
    await goToNextLesson(topicId);
  }

  // ==========================================
  // SECTION 9: QUIZ SOLVER LOGIC
  // ==========================================
  async function performQuizAnswer() {
    try {
      const subjectId = getSubjectId();
      const quizId = getCurrentLessonIdFromUrl();
      if (!subjectId || !quizId)
        throw new Error("Could not extract Subject/Quiz ID.");

      const metaCsrf = document
        .querySelector('meta[name="csrf-token"]')
        ?.getAttribute("content");
      let tokens = {};
      try {
        tokens = getTokens();
      } catch (_) {}

      const headers = {
        accept: "application/json, */*",
        "content-type": "application/json",
        authorization:
          capturedHeaders["authorization"] ||
          (tokens.auth ? `Bearer ${tokens.auth}` : ""),
        "x-csrf-token": capturedHeaders["x-csrf-token"] || metaCsrf || "",
        "x-xsrf-token": capturedHeaders["x-xsrf-token"] || tokens.xsrf || "",
      };

      if (!headers["authorization"]) {
        const savedAuth = getSavedAuth();
        if (savedAuth) {
          headers["authorization"] = "Bearer " + savedAuth;
        } else {
          throw new Error(
            "Missing Auth Header. Refresh the quiz page once to capture auth session.",
          );
        }
      }

      setAutoBtnText("Auto: Fetching Quiz Data...");

      const quizRes = await _origFetch(
        `https://e-ed.e-tech.ac.th/api/quiz/${quizId}`,
        { headers },
      );

      if (!quizRes.ok)
        throw new Error(`HTTP ${quizRes.status} fetching quiz data.`);

      const rawQuizPayload = await quizRes.json();
      const quizData = Array.isArray(rawQuizPayload)
        ? rawQuizPayload
        : rawQuizPayload.data || [];
      if (quizData.length === 0)
        throw new Error("Quiz question array is empty.");

      if (!sessionStorage.getItem(AUTO_RUN_KEY)) return;

      setAutoBtnText("Phase 1: Initial DOM Pass...");
      await answerAllQuestionsInDOM(quizData);

      if (!sessionStorage.getItem(AUTO_RUN_KEY)) return;

      const TARGET_PERCENT = 70;

      try {
        setAutoBtnText("Checking initial pass score...");
        const verifyRes = await _origFetch(
          `https://e-ed.e-tech.ac.th/api/quiz/${quizId}`,
          { headers },
        );
        if (verifyRes.ok) {
          const verifyData = await verifyRes.json();
          const currentScore = extractScorePercent(verifyData);
          if (currentScore !== null && currentScore >= TARGET_PERCENT) {
            setAutoBtnText(
              `Passed on 1st attempt (${currentScore}%)! Moving next...`,
            );
            await new Promise((r) => setTimeout(r, 800));
            isTaskRunning = false;
            await goToNextLesson(getCurrentLessonIdFromUrl());
            return;
          }
        }
      } catch (_) {}

      let openid = capturedOpenId;
      if (!openid && tokens.auth) {
        const parsed = getOpenIdFromToken(tokens.auth);
        if (parsed) openid = String(parsed);
      }
      let recid =
        capturedRecId || Math.floor(Math.random() * 2000000) + 1000000;

      if (!recid || !openid) {
        throw new Error(
          "Could not capture valid session IDs (recid/openid). Please click any choice manually and try again.",
        );
      }

      const MAX_ATTEMPTS = quizData.length * 6;
      const knownCorrect = {};
      const knownIncorrect = {};
      const currentAnswers = {};

      quizData.forEach((q) => {
        const qId = Number(q.quizid || q.id || q.itemid);
        knownIncorrect[qId] = new Set();
        const choices = q.choices || q.options || q.choices_show_answer || [];
        if (choices.length > 0) {
          const randomChoice =
            choices[Math.floor(Math.random() * choices.length)];
          currentAnswers[qId] = getChoiceDbId(randomChoice);
        }
      });

      let attempt = 0;
      let lastScore = null;
      let activeMutatedQId = null;
      let mutatedOldChoice = null;
      let solved = false;

      while (attempt < MAX_ATTEMPTS) {
        if (!sessionStorage.getItem(AUTO_RUN_KEY)) return;
        attempt++;

        const payloadAnswers = quizData.map((q) => {
          const qId = Number(q.quizid || q.id || q.itemid);
          return {
            quizid: qId,
            quiz_type: q.quiz_type || "M",
            ans: currentAnswers[qId],
          };
        });

        const sendRes = await _origFetch(
          `https://e-ed.e-tech.ac.th/api/quiz/v2/${quizId}/sendAnswer`,
          {
            method: "POST",
            headers,
            body: JSON.stringify({
              recid: Number(recid),
              itemid: Number(quizId),
              openid: String(openid),
              courseid: Number(subjectId),
              ans: payloadAnswers,
            }),
          },
        );

        if (!sendRes.ok) {
          if (sendRes.status === 401 || sendRes.status === 419) {
            clearTokens();
            throw new Error("Token expired.");
          }
          await new Promise((r) => setTimeout(r, 600));
          continue;
        }

        const result = await sendRes.json();
        const scorePercent = extractScorePercent(result);

        if (activeMutatedQId && lastScore !== null && scorePercent !== null) {
          if (scorePercent > lastScore) {
            knownIncorrect[activeMutatedQId].add(mutatedOldChoice);
          } else if (scorePercent < lastScore) {
            knownIncorrect[activeMutatedQId].add(
              currentAnswers[activeMutatedQId],
            );
            currentAnswers[activeMutatedQId] = mutatedOldChoice;
            knownCorrect[activeMutatedQId] = mutatedOldChoice;
          } else {
            knownIncorrect[activeMutatedQId].add(
              currentAnswers[activeMutatedQId],
            );
          }
        }

        lastScore = scorePercent;

        if (scorePercent !== null && !isNaN(scorePercent)) {
          setAutoBtnText("Attempt #" + attempt + " | " + scorePercent + "%");
          if (Number(scorePercent) >= TARGET_PERCENT) {
            solved = true;
            break;
          }
        }

        const candidateQuestions = quizData.filter((q) => {
          const qId = Number(q.quizid || q.id || q.itemid);
          return !knownCorrect[qId];
        });

        let mutationSet = false;
        for (const targetQ of candidateQuestions) {
          const targetQId = Number(
            targetQ.quizid || targetQ.id || targetQ.itemid,
          );
          const choices =
            targetQ.choices ||
            targetQ.options ||
            targetQ.choices_show_answer ||
            [];

          const remainingChoices = choices.filter((c) => {
            const cDbId = getChoiceDbId(c);
            return (
              cDbId !== currentAnswers[targetQId] &&
              !knownIncorrect[targetQId].has(cDbId)
            );
          });

          if (remainingChoices.length > 0) {
            activeMutatedQId = targetQId;
            mutatedOldChoice = currentAnswers[targetQId];
            currentAnswers[targetQId] = getChoiceDbId(remainingChoices[0]);
            mutationSet = true;
            break;
          } else {
            knownCorrect[targetQId] = currentAnswers[targetQId];
          }
        }

        if (!mutationSet) activeMutatedQId = null;
        await new Promise((r) => setTimeout(r, 350));
      }

      if (!solved)
        throw new Error(
          `Could not reach ${TARGET_PERCENT}% within maximum attempts.`,
        );

      if (!sessionStorage.getItem(AUTO_RUN_KEY)) return;

      setAutoBtnText("Phase 2: Submitting on DOM...");
      await answerAllQuestionsInDOM(quizData, currentAnswers);

      setAutoBtnText("Auto: Quiz Completed!");
      await new Promise((r) => setTimeout(r, 500));

      if (!sessionStorage.getItem(AUTO_RUN_KEY)) return;
      isTaskRunning = false;
      await goToNextLesson(getCurrentLessonIdFromUrl());
    } catch (err) {
      alert("Quiz Solver Error:\n" + err.message);
      sessionStorage.removeItem(AUTO_RUN_KEY);
      updateAutoBtnUI();
    } finally {
      isTaskRunning = false;
    }
  }

  // ==========================================
  // SECTION 10: TASK CONTROLLER & INITIALIZATION
  // ==========================================
  async function executeCurrentTask() {
    if (!sessionStorage.getItem(AUTO_RUN_KEY)) return;
    if (isTaskRunning) return;
    isTaskRunning = true;

    setAutoBtnText("Auto: Waiting for content...");
    await waitForContentReady();

    if (!sessionStorage.getItem(AUTO_RUN_KEY)) {
      isTaskRunning = false;
      updateAutoBtnUI();
      return;
    }

    if (location.pathname.includes("/lesson")) {
      await processAllLessonSubTabs();
    } else if (location.pathname.includes("/quiz/")) {
      await performQuizAnswer();
    } else {
      setAutoBtnText("Auto: Standby...");
      isTaskRunning = false;
    }
  }

  function updateApp() {
    const isActionablePage =
      location.pathname.includes("/lesson") ||
      location.pathname.includes("/quiz/");
    if (isActionablePage) {
      addAutoButton();
    } else {
      document.getElementById("eedAutoBtn")?.remove();
    }

    renderProgressionWidget();

    const sid = getSubjectId();
    if (sid) fetchCourseLessons(sid);

    if (isActionablePage && sessionStorage.getItem(AUTO_RUN_KEY)) {
      executeCurrentTask();
    }
  }

  let lastUrl = location.href;
  let navDebounceTimer = null;

  injectStyles();

  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      sniffedHeartbeatPayload = null;
      isTaskRunning = false;
      lessonsLoaded = false;
      lessonsPromise = null;

      clearTimeout(navDebounceTimer);
      navDebounceTimer = setTimeout(updateApp, 200);
    }
  }).observe(document.body || document.documentElement, {
    subtree: true,
    childList: true,
  });

  startGlobalBackgroundPulseLoop();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", updateApp);
  } else {
    updateApp();
  }
})();
