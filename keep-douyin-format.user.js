// ==UserScript==
// @name         Douyin Fenshen Keep Format
// @namespace    codex.local
// @version      0.1.0
// @description  Keep the Douyin Fenshen web app on ?module=format instead of redirecting to /ai_guest.
// @match        https://fenshen.douyin.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
  "use strict";

  var TARGET_PATH = "/";
  var TARGET_MODULE = "format";
  var BLOCKED_PATHS = new Set(["/ai_guest"]);

  function toUrl(input) {
    try {
      return new URL(String(input), location.origin);
    } catch (error) {
      return null;
    }
  }

  function ensureFormatUrl(input) {
    var url = toUrl(input || location.href);
    if (!url || url.origin !== location.origin) {
      return input;
    }

    if (BLOCKED_PATHS.has(url.pathname) || url.pathname === TARGET_PATH) {
      url.pathname = TARGET_PATH;
      url.searchParams.set("module", TARGET_MODULE);
      return url.pathname + url.search + url.hash;
    }

    return input;
  }

  function isBlockedUrl(input) {
    var url = toUrl(input);
    return !!url && url.origin === location.origin && BLOCKED_PATHS.has(url.pathname);
  }

  function pinCurrentUrl() {
    var nextUrl = ensureFormatUrl(location.href);
    if (typeof nextUrl === "string" && nextUrl !== location.pathname + location.search + location.hash) {
      history.replaceState(history.state, "", nextUrl);
    }
  }

  function patchAvatarInfo(payload) {
    if (!payload || typeof payload !== "object") {
      return payload;
    }

    var avatarInfo = payload.data && payload.data.avatar_info;
    if (avatarInfo && Object.prototype.hasOwnProperty.call(avatarInfo, "in_ai_guest_allow_list")) {
      avatarInfo.in_ai_guest_allow_list = false;
    }

    return payload;
  }

  var originalJsonParse = JSON.parse;
  JSON.parse = function patchedJsonParse(text, reviver) {
    var parsed = originalJsonParse.call(this, text, reviver);
    return patchAvatarInfo(parsed);
  };

  var originalPushState = history.pushState.bind(history);
  var originalReplaceState = history.replaceState.bind(history);

  history.pushState = function patchedPushState(state, title, url) {
    if (isBlockedUrl(url)) {
      return;
    }

    return originalPushState(state, title, ensureFormatUrl(url));
  };

  history.replaceState = function patchedReplaceState(state, title, url) {
    if (isBlockedUrl(url)) {
      return;
    }

    return originalReplaceState(state, title, ensureFormatUrl(url));
  };

  pinCurrentUrl();
  addEventListener("popstate", pinCurrentUrl, true);
  addEventListener("hashchange", pinCurrentUrl, true);

  // The site is a SPA and may retry route changes after data load.
  setInterval(pinCurrentUrl, 500);
})();
