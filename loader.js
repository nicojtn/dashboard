/* Dashboard-Loader: lädt vault.json, entschlüsselt im Browser (WebCrypto) und startet die App.
   Enthält keine Inhalte. Format: Datenschlüssel (AES-256-GCM) verschlüsselt die App;
   der Datenschlüssel ist mit einem PBKDF2-SHA256-Schlüssel aus dem Passwort verpackt
   und optional (Face ID) mit einem Schlüssel aus der WebAuthn-PRF-Erweiterung. */
(function () {
  "use strict";
  var NS = "dash.v1.";                       // eigener Namensraum (github.io teilt localStorage je Account)
  var K_REMEMBER = NS + "key", K_FACE = NS + "faceid", K_OFFER = NS + "faceid-offer";
  var te = new TextEncoder(), td = new TextDecoder();
  var subtle = window.crypto && window.crypto.subtle;
  var $ = function (id) { return document.getElementById(id); };
  var vault = null, started = false;

  function b64(buf) { var s = "", b = new Uint8Array(buf); for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function unb64(s) { var r = atob(s), b = new Uint8Array(r.length); for (var i = 0; i < r.length; i++) b[i] = r.charCodeAt(i); return b; }
  function rnd(n) { return window.crypto.getRandomValues(new Uint8Array(n)); }
  function ls(k, v) { try { if (v === undefined) return localStorage.getItem(k); if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { return null; } }
  function err(t) { $("err").textContent = t || ""; }
  function busy(on) { ["pw-btn", "face-btn", "offer-yes", "offer-no"].forEach(function (id) { var e = $(id); if (e) e.disabled = !!on; }); }

  async function keyIdOf(raw) { var h = await subtle.digest("SHA-256", raw); return b64(h.slice(0, 12)); }
  async function importDK(raw) { return subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]); }
  async function gcmOpen(key, ivB64, ctB64, aad) { return subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64), additionalData: te.encode(aad) }, key, unb64(ctB64)); }

  async function loadVault() {
    var r = await fetch("vault.json?ts=" + Date.now(), { cache: "no-store" });
    if (!r.ok) throw new Error("Daten konnten nicht geladen werden (" + r.status + ").");
    vault = await r.json();
  }

  // --- Passwort ---
  async function dkFromPassword(pw) {
    var base = await subtle.importKey("raw", te.encode(pw), "PBKDF2", false, ["deriveKey"]);
    var kek = await subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: unb64(vault.kdf.salt), iterations: vault.kdf.iter }, base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    return new Uint8Array(await gcmOpen(kek, vault.wrap.iv, vault.wrap.ct, "dash-wrap-v1"));
  }

  // --- Face ID (WebAuthn PRF) ---
  function faceRec() { try { return JSON.parse(ls(K_FACE) || "null"); } catch (e) { return null; } }
  function faceCapableSync() { return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext); }
  async function faceCapable() {
    if (!faceCapableSync()) return false;
    try { return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch (e) { return false; }
  }
  async function wrapKeyFromPrf(prfOut, salt) {
    var ikm = await subtle.importKey("raw", prfOut, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: salt, info: te.encode("dash-faceid-wrap-v1") }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function prfGet(credId, prfSalt) {
    var a = await navigator.credentials.get({ publicKey: {
      challenge: rnd(32), rpId: location.hostname, timeout: 60000, userVerification: "required",
      allowCredentials: [{ type: "public-key", id: credId, transports: ["internal", "hybrid"] }],
      extensions: { prf: { eval: { first: prfSalt } } } } });
    var ext = a.getClientExtensionResults ? a.getClientExtensionResults() : {};
    var out = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    if (!out) throw new Error("PRF");
    return new Uint8Array(out);
  }
  function friendly(m) { var e = new Error(m); e.friendly = true; return e; }
  async function enableFaceId(dkRaw) {
    if (!(await faceCapable())) throw friendly("Face ID ist in diesem Browser nicht verfügbar. Das Passwort funktioniert weiter.");
    var prfSalt = rnd(32);
    var cred = await navigator.credentials.create({ publicKey: {
      challenge: rnd(32), rp: { name: "Dashboard", id: location.hostname },
      user: { id: rnd(16), name: "dashboard", displayName: "Dashboard" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "required", requireResidentKey: true },
      timeout: 60000, attestation: "none", extensions: { prf: { eval: { first: prfSalt } } } } });
    var ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
    if (!ext || !ext.prf || ext.prf.enabled === false) throw friendly("Dieses Gerät unterstützt Face ID für das Dashboard nicht (benötigt iOS/iPadOS 18 bzw. Safari 18 oder neuer). Das Passwort funktioniert weiter.");
    var out = ext.prf.results && ext.prf.results.first ? new Uint8Array(ext.prf.results.first) : await prfGet(new Uint8Array(cred.rawId), prfSalt);
    var wk = await wrapKeyFromPrf(out, prfSalt), iv = rnd(12);
    var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: te.encode("dash-faceid-v1") }, wk, dkRaw);
    ls(K_FACE, JSON.stringify({ credId: b64(cred.rawId), prfSalt: b64(prfSalt), iv: b64(iv), ct: b64(ct), keyId: vault.keyId }));
  }
  async function dkFromFace() {
    var r = faceRec(); if (!r) throw new Error("none");
    var out = await prfGet(unb64(r.credId), unb64(r.prfSalt));
    var wk = await wrapKeyFromPrf(out, unb64(r.prfSalt));
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(r.iv), additionalData: te.encode("dash-faceid-v1") }, wk, unb64(r.ct)));
  }

  // --- App starten ---
  async function openWith(dkRaw) {
    if ((await keyIdOf(dkRaw)) !== vault.keyId) throw new Error("keyid");
    var dk = await importDK(dkRaw);
    var plain = td.decode(await gcmOpen(dk, vault.data.iv, vault.data.ct, "dash-data-v1"));
    return JSON.parse(plain);
  }
  function start(pkg, dkRaw) {
    if (started) return; started = true;
    window.__DASH__ = pkg.data;
    window.__DASH_API__ = {
      logout: function () { ls(K_REMEMBER, null); location.reload(); },
      faceIdState: function () { return faceRec() ? "on" : (faceCapableSync() ? "off" : "unsupported"); },
      enableFaceId: function () { return enableFaceId(dkRaw).catch(function (e) { throw (e && e.friendly) ? e : friendly(e && e.name === "NotAllowedError" ? "Face ID wurde abgebrochen." : "Face ID konnte nicht eingerichtet werden. Das Passwort funktioniert weiter."); }); },
      disableFaceId: function () { ls(K_FACE, null); ls(K_OFFER, "no"); }
    };
    $("lock").hidden = true;
    var url = URL.createObjectURL(new Blob([pkg.app], { type: "text/javascript" }));
    var s = document.createElement("script"); s.src = url; s.onload = function () { URL.revokeObjectURL(url); };
    document.body.appendChild(s);
  }
  async function afterPassword(pkg, dkRaw) {
    // Nach erstem Passwort-Login Face ID anbieten (nur wenn das Gerät es grundsätzlich kann).
    if (!faceRec() && ls(K_OFFER) !== "no" && (await faceCapable())) {
      $("pw-form").hidden = true; $("pane-face").hidden = true; $("pane-offer").hidden = false; busy(false); $("pw-btn").textContent = "Entsperren";
      $("lock-sub").textContent = "Entsperrt.";
      $("note").textContent = "Face ID nutzt einen Passkey im iCloud-Schlüsselbund. Auf dem Gerät wird nur ein damit verschlüsselter Schlüssel gespeichert – nie das Passwort.";
      $("offer-no").onclick = function () { ls(K_OFFER, "no"); start(pkg, dkRaw); };
      $("offer-yes").onclick = async function () {
        err(""); busy(true);
        try { await enableFaceId(dkRaw); start(pkg, dkRaw); }
        catch (e) {
          busy(false);
          var m = e && e.name === "NotAllowedError" ? "Face ID wurde abgebrochen. Du kannst es später in der Seitenleiste aktivieren." : (e && e.friendly ? e.message : "Face ID konnte nicht eingerichtet werden. Das Passwort funktioniert weiter.");
          err(m); $("offer-yes").textContent = "Erneut versuchen"; $("offer-no").textContent = "Weiter ohne Face ID";
          $("offer-no").onclick = function () { start(pkg, dkRaw); };
        }
      };
      return;
    }
    start(pkg, dkRaw);
  }

  async function onPassword(ev) {
    ev.preventDefault(); err("");
    var pw = $("pw").value; if (!pw) { err("Bitte das Passwort eingeben."); return; }
    busy(true); $("pw-btn").textContent = "Entsperre …";
    try {
      var dkRaw;
      try { dkRaw = await dkFromPassword(pw); }
      catch (e) { throw new Error("wrong"); }
      var pkg = await openWith(dkRaw);
      $("pw").value = "";
      if ($("remember").checked) ls(K_REMEMBER, JSON.stringify({ k: b64(dkRaw), id: vault.keyId })); else ls(K_REMEMBER, null);
      await afterPassword(pkg, dkRaw);
    } catch (e) {
      busy(false); $("pw-btn").textContent = "Entsperren";
      $("pw").classList.add("bad"); $("pw").select();
      err(e && e.message === "wrong" ? "Das Passwort stimmt leider nicht. Bitte noch einmal versuchen." : "Entsperren hat nicht geklappt. Bitte Seite neu laden.");
    }
  }
  async function onFace() {
    err(""); busy(true); $("face-btn").textContent = "Warte auf Face ID …";
    try { var dkRaw = await dkFromFace(); start(await openWith(dkRaw), dkRaw); }
    catch (e) {
      busy(false); $("face-btn").textContent = "Mit Face ID entsperren";
      if (e && e.message === "keyid") { ls(K_FACE, null); $("pane-face").hidden = true; err("Face ID passt nicht mehr zum aktuellen Schlüssel. Bitte mit Passwort entsperren und Face ID neu aktivieren."); }
      else if (e && e.name === "NotAllowedError") err("Face ID abgebrochen. Du kannst auch das Passwort verwenden.");
      else err("Face ID hat nicht geklappt. Bitte das Passwort verwenden.");
      $("pw").focus();
    }
  }

  async function init() {
    $("pw").addEventListener("input", function () { this.classList.remove("bad"); err(""); });
    $("pw-form").addEventListener("submit", onPassword);
    if (!subtle) { err("Dieser Browser unterstützt keine sichere Entschlüsselung (WebCrypto fehlt)."); busy(true); return; }
    try { await loadVault(); } catch (e) { err(e.message); busy(true); return; }
    // Angemeldet bleiben: gespeicherten Datenschlüssel versuchen
    var rem = null; try { rem = JSON.parse(ls(K_REMEMBER) || "null"); } catch (e) { rem = null; }
    if (rem && rem.id === vault.keyId) {
      try { var raw = unb64(rem.k); start(await openWith(raw), raw); return; } catch (e) { ls(K_REMEMBER, null); }
    } else if (rem) { ls(K_REMEMBER, null); }
    var fr = faceRec();
    if (fr && fr.keyId !== vault.keyId) { ls(K_FACE, null); fr = null; }
    if (fr && faceCapableSync()) {
      $("pane-face").hidden = false; $("face-btn").onclick = onFace;
      $("remember").checked = false;                 // bei aktivem Face ID standardmäßig aus
      $("lock-sub").textContent = "Mit Face ID oder Passwort entsperren.";
    } else { $("pw").focus(); }
  }
  init();
})();
