/* Dashboard-Loader: lädt vault.json, entschlüsselt im Browser (WebCrypto) und startet die App.
   Enthält keine Inhalte. Format: Datenschlüssel (AES-256-GCM) verschlüsselt die App;
   der Datenschlüssel ist mit einem PBKDF2-SHA256-Schlüssel aus dem Passwort verpackt
   und optional (Face ID) mit einem Schlüssel aus der WebAuthn-PRF-Erweiterung. */
(function () {
  "use strict";
  var NS = "dash.v1.";                       // eigener Namensraum (github.io teilt localStorage je Account)
  var K_REMEMBER = NS + "key", K_FACE = NS + "faceid", K_OFFER = NS + "faceid-offer", K_PIN = NS + "pin";
  var PIN_ITER = 300000, PIN_MAX_FAILS = 5;
  var te = new TextEncoder(), td = new TextDecoder();
  var subtle = window.crypto && window.crypto.subtle;
  var $ = function (id) { return document.getElementById(id); };
  var vault = null, started = false;

  function b64(buf) { var s = "", b = new Uint8Array(buf); for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function unb64(s) { var r = atob(s), b = new Uint8Array(r.length); for (var i = 0; i < r.length; i++) b[i] = r.charCodeAt(i); return b; }
  function rnd(n) { return window.crypto.getRandomValues(new Uint8Array(n)); }
  function ls(k, v) { try { if (v === undefined) return localStorage.getItem(k); if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { return null; } }
  function err(t) { $("err").textContent = t || ""; }
  function busy(on) { ["pw-btn", "face-btn", "offer-yes", "offer-no", "offer-pin", "pin-btn", "pin-save"].forEach(function (id) { var e = $(id); if (e) e.disabled = !!on; }); }

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
  // credentials.get/create werden jeweils direkt im Tipp-Handler aufgerufen (kein await davor), sonst greift iOS ggf. nicht auf Face ID zurück.
  function prfGet(credId, prfSalt, transports) {
    return navigator.credentials.get({ publicKey: {
      challenge: rnd(32), rpId: location.hostname, timeout: 120000, userVerification: "required", hints: ["client-device"],
      allowCredentials: [{ type: "public-key", id: credId, transports: transports && transports.length ? transports : ["internal", "hybrid"] }],
      extensions: { prf: { eval: { first: prfSalt } } } } }).then(function (a) {
      var ext = a.getClientExtensionResults ? a.getClientExtensionResults() : {};
      var out = ext && ext.prf && ext.prf.results && ext.prf.results.first;
      if (!out) throw new Error("PRF");
      return new Uint8Array(out);
    });
  }
  function faceErr(e) { throw (e && e.friendly) ? e : friendly(e && e.name === "NotAllowedError" ? "Face ID wurde abgebrochen oder ist abgelaufen. Bitte noch einmal tippen." : "Face ID konnte nicht eingerichtet werden. Das Passwort funktioniert weiter."); }
  var CODE_HINT = "Fragt das iPhone statt Face ID nach dem Gerätecode? Der Code entsperrt genauso. Wenn das immer passiert: nach dem Passwort-Login in der Seitenleiste eine App-PIN festlegen.";
  function friendly(m) { var e = new Error(m); e.friendly = true; return e; }
  var pendingFace = null;   // Passkey angelegt, aber PRF-Ergebnis kommt erst mit dem nächsten Tipp
  async function saveFace(dkRaw, credIdRaw, prfSalt, transports, out) {
    var wk = await wrapKeyFromPrf(out, prfSalt), iv = rnd(12);
    var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: te.encode("dash-faceid-v1") }, wk, dkRaw);
    ls(K_FACE, JSON.stringify({ credId: b64(credIdRaw), prfSalt: b64(prfSalt), tr: transports, iv: b64(iv), ct: b64(ct), keyId: vault.keyId }));
    pendingFace = null;
    return "on";
  }
  // Rückgabe: "on" (aktiv) oder "confirm" (noch einmal tippen: confirmFaceId)
  function enableFaceId(dkRaw) {
    if (!faceCapableSync()) return Promise.reject(friendly("Face ID ist in diesem Browser nicht verfügbar. Das Passwort funktioniert weiter."));
    var prfSalt = rnd(32);
    return navigator.credentials.create({ publicKey: {
      challenge: rnd(32), rp: { name: "Dashboard", id: location.hostname },
      user: { id: rnd(16), name: "dashboard", displayName: "Dashboard" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "required", requireResidentKey: true },
      hints: ["client-device"], timeout: 120000, attestation: "none", extensions: { prf: { eval: { first: prfSalt } } } } }).then(function (cred) {
      var ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
      if (!ext || !ext.prf || ext.prf.enabled === false) throw friendly("Dieses Gerät unterstützt Face ID für das Dashboard nicht (benötigt iOS/iPadOS 18 bzw. Safari 18 oder neuer). Das Passwort funktioniert weiter.");
      var tr = []; try { tr = cred.response.getTransports ? cred.response.getTransports() : []; } catch (e) { tr = []; }
      if (tr.indexOf("internal") < 0) tr.push("internal");
      var raw = new Uint8Array(cred.rawId);
      if (ext.prf.results && ext.prf.results.first) return saveFace(dkRaw, raw, prfSalt, tr, new Uint8Array(ext.prf.results.first));
      pendingFace = { dkRaw: dkRaw, raw: raw, prfSalt: prfSalt, tr: tr };
      return "confirm";
    });
  }
  function confirmFaceId() {
    var p = pendingFace; if (!p) return Promise.reject(friendly("Bitte Face ID neu aktivieren."));
    return prfGet(p.raw, p.prfSalt, p.tr).then(function (out) { return saveFace(p.dkRaw, p.raw, p.prfSalt, p.tr, out); });
  }
  async function dkFromFace() {
    var r = faceRec(); if (!r) throw new Error("none");
    var out = await prfGet(unb64(r.credId), unb64(r.prfSalt), r.tr);
    var wk = await wrapKeyFromPrf(out, unb64(r.prfSalt));
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(r.iv), additionalData: te.encode("dash-faceid-v1") }, wk, unb64(r.ct)));
  }

  // --- App-PIN (Fallback, falls Face ID nicht zuverlässig klappt) ---
  // Datenschlüssel doppelt verpackt: innen mit PBKDF2(PIN), außen mit einem nicht exportierbaren Geräteschlüssel aus IndexedDB.
  // Nach PIN_MAX_FAILS Fehlversuchen wird die PIN gelöscht – dann nur noch Passwort (oder Face ID).
  function pinRec() { try { return JSON.parse(ls(K_PIN) || "null"); } catch (e) { return null; } }
  function idb(mode, fn) {
    return new Promise(function (res, rej) {
      if (!window.indexedDB) { rej(new Error("idb")); return; }
      var rq = indexedDB.open("dash-v1", 1);
      rq.onupgradeneeded = function () { rq.result.createObjectStore("keys"); };
      rq.onerror = function () { rej(rq.error); };
      rq.onsuccess = function () {
        var db = rq.result, tx = db.transaction("keys", mode), st = tx.objectStore("keys"), out = fn(st);
        tx.oncomplete = function () { db.close(); res(out && out.result !== undefined ? out.result : undefined); };
        tx.onerror = function () { db.close(); rej(tx.error); };
      };
    });
  }
  async function deviceKey(create) {
    var k = await idb("readonly", function (st) { return st.get("device"); });
    if (k || !create) return k || null;
    k = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await idb("readwrite", function (st) { st.put(k, "device"); });
    return k;
  }
  async function pinKey(pin, salt) {
    var base = await subtle.importKey("raw", te.encode(pin), "PBKDF2", false, ["deriveKey"]);
    return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: PIN_ITER }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function setPin(dkRaw, pin) {
    if (!/^\d{4,6}$/.test(pin || "")) throw friendly("Die PIN braucht 4 bis 6 Ziffern.");
    var dev; try { dev = await deviceKey(true); } catch (e) { dev = null; }
    if (!dev) throw friendly("Dieser Browser kann keinen Geräteschlüssel speichern – App-PIN nicht möglich.");
    var salt = rnd(16), iv1 = rnd(12), iv2 = rnd(12);
    var inner = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: iv1, additionalData: te.encode("dash-pin-v1") }, await pinKey(pin, salt), dkRaw));
    var outer = await subtle.encrypt({ name: "AES-GCM", iv: iv2, additionalData: te.encode("dash-pin-dev-v1") }, dev, inner);
    ls(K_PIN, JSON.stringify({ salt: b64(salt), iv1: b64(iv1), iv2: b64(iv2), ct: b64(outer), keyId: vault.keyId, fails: 0 }));
  }
  async function dkFromPin(pin) {
    var r = pinRec(); if (!r) throw new Error("none");
    if ((r.fails || 0) >= PIN_MAX_FAILS) { ls(K_PIN, null); throw new Error("locked"); }
    r.fails = (r.fails || 0) + 1; ls(K_PIN, JSON.stringify(r));          // Versuch zuerst zählen (Neuladen setzt nicht zurück)
    var dev = await deviceKey(false); if (!dev) { ls(K_PIN, null); throw new Error("nodev"); }
    var inner = await subtle.decrypt({ name: "AES-GCM", iv: unb64(r.iv2), additionalData: te.encode("dash-pin-dev-v1") }, dev, unb64(r.ct));
    var raw;
    try { raw = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(r.iv1), additionalData: te.encode("dash-pin-v1") }, await pinKey(pin, unb64(r.salt)), inner)); }
    catch (e) {
      await new Promise(function (ok) { setTimeout(ok, 600 * r.fails); });   // wachsende Wartezeit
      if (r.fails >= PIN_MAX_FAILS) { ls(K_PIN, null); throw new Error("locked"); }
      throw new Error("wrongpin:" + (PIN_MAX_FAILS - r.fails));
    }
    r.fails = 0; ls(K_PIN, JSON.stringify(r));
    return raw;
  }
  function removePin() { ls(K_PIN, null); }

  // --- App starten ---
  async function openWith(dkRaw) {
    if ((await keyIdOf(dkRaw)) !== vault.keyId) throw new Error("keyid");
    var dk = await importDK(dkRaw);
    var plain = td.decode(await gcmOpen(dk, vault.data.iv, vault.data.ct, "dash-data-v1"));
    return JSON.parse(plain);
  }
  function start(pkg, dkRaw) {
    if (started) return; started = true;
    var cur = pkg;
    window.__DASH__ = pkg.data;
    window.__DASH_API__ = {
      logout: function () { ls(K_REMEMBER, null); location.reload(); },
      faceIdState: function () { return faceRec() ? "on" : (faceCapableSync() ? "off" : "unsupported"); },
      enableFaceId: function () { return enableFaceId(dkRaw).catch(faceErr); },
      pinState: function () { return pinRec() ? "on" : (window.indexedDB ? "off" : "unsupported"); },
      setPin: function (pin) { return setPin(dkRaw, pin); },
      removePin: removePin,
      confirmFaceId: function () { return confirmFaceId().catch(faceErr); },
      disableFaceId: function () { ls(K_FACE, null); ls(K_OFFER, "no"); },
      // Verschlüsselte Zusatzdatei laden und im Browser entschlüsseln -> Blob
      file: async function (name, type) {
        var r = await fetch(name + ".bin?ts=" + Date.now(), { cache: "no-store" });
        if (!r.ok) throw new Error("Datei nicht gefunden (" + r.status + ")");
        var buf = new Uint8Array(await r.arrayBuffer());
        var key = await importDK(dkRaw);
        var pt = await subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12), additionalData: te.encode("dash-file-" + name + "-v1") }, key, buf.slice(12));
        return new Blob([pt], { type: type || "application/octet-stream" });
      }
    };
    // Neu zeichnen (z. B. mit Live-Kursen): App-Bundle erneut ausführen, Daten bleiben window.__DASH__
    window.__DASH_API__.remount = function () { runApp(cur.app); };
    // Neuere vault.json (nach Webhook-Refresh) holen, mit dem vorhandenen Schlüssel entschlüsseln und an Ort und Stelle neu zeichnen.
    // true = neuer Stand angezeigt, false = noch nichts Neues.
    window.__DASH_API__.checkVault = async function () {
      var r = await fetch("vault.json?ts=" + Date.now(), { cache: "no-store" });
      if (!r.ok) return false;
      var v = await r.json();
      if (!v || !v.data || v.data.iv === vault.data.iv) return false;
      if (v.keyId !== vault.keyId) return false; // anderer Datenschlüssel: erst beim nächsten Entsperren
      var dk = await importDK(dkRaw);
      var next = JSON.parse(td.decode(await gcmOpen(dk, v.data.iv, v.data.ct, "dash-data-v1")));
      vault = v;
      if ((next.data && next.data.builtTs || 0) <= (cur.data && cur.data.builtTs || 0)) return false;
      cur = next; window.__DASH__ = next.data; runApp(next.app);
      return true;
    };
    $("lock").hidden = true;
    runApp(cur.app);
  }
  function runApp(code) {
    var url = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
    var s = document.createElement("script"); s.src = url;
    s.onload = function () { URL.revokeObjectURL(url); s.remove(); };
    document.body.appendChild(s);
  }
  async function afterPassword(pkg, dkRaw) {
    // Nach erstem Passwort-Login Face ID anbieten (nur wenn das Gerät es grundsätzlich kann).
    var fc = await faceCapable();
    if (!faceRec() && !pinRec() && ls(K_OFFER) !== "no") {
      if (!fc) $("offer-yes").hidden = true;
      $("pw-form").hidden = true; $("pane-face").hidden = true; $("pane-offer").hidden = false; busy(false); $("pw-btn").textContent = "Entsperren";
      $("lock-sub").textContent = "Entsperrt.";
      $("note").textContent = "Face ID nutzt einen Passkey im iCloud-Schlüsselbund. Die App-PIN gilt nur auf diesem Gerät; nach 5 Fehlversuchen wird sie gelöscht. Gespeichert wird nie das Passwort, nur ein verschlüsselter Schlüssel.";
      $("offer-no").onclick = function () { ls(K_OFFER, "no"); start(pkg, dkRaw); };
      $("offer-pin").onclick = function () { $("pin-setup").hidden = false; $("offer-pin").hidden = true; err(""); $("pin-new").focus(); };
      $("pin-setup").onsubmit = async function (ev) {
        ev.preventDefault(); err("");
        var a = $("pin-new").value, b2 = $("pin-new2").value;
        if (!/^\d{4,6}$/.test(a)) { err("Die PIN braucht 4 bis 6 Ziffern."); return; }
        if (a !== b2) { err("Die beiden PINs stimmen nicht überein."); return; }
        busy(true);
        try { await setPin(dkRaw, a); $("pin-new").value = ""; $("pin-new2").value = ""; start(pkg, dkRaw); }
        catch (e) { busy(false); err(e && e.friendly ? e.message : "PIN konnte nicht gespeichert werden. Das Passwort funktioniert weiter."); }
      };
      var onConfirm = function () {
        err(""); busy(true);
        confirmFaceId().then(function () { start(pkg, dkRaw); }, function (e) {
          busy(false); err(e && e.friendly ? e.message : (e && e.name === "NotAllowedError" ? "Face ID wurde abgebrochen. Bitte noch einmal tippen." : "Face ID konnte nicht bestätigt werden. Das Passwort funktioniert weiter."));
        });
      };
      $("offer-yes").onclick = async function () {
        err(""); busy(true);
        try {
          var res = await enableFaceId(dkRaw);   // create() wird synchron im Tipp aufgerufen
          if (res === "confirm") {
            busy(false); $("offer-yes").textContent = "Face ID bestätigen"; $("offer-yes").onclick = onConfirm;
            $("note").textContent = "Passkey ist angelegt. Bitte noch einmal tippen, damit Face ID den Schlüssel freigibt.";
            return;
          }
          start(pkg, dkRaw);
        }
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
      else if (e && e.name === "NotAllowedError") err("Face ID abgebrochen oder abgelaufen. Noch einmal tippen – oder das Passwort verwenden.");
      else err("Face ID hat nicht geklappt. Bitte das Passwort verwenden.");
      $("pw").focus();
    }
  }

  async function onPin(ev) {
    ev.preventDefault(); err("");
    var pin = $("pin").value; if (!/^\d{4,6}$/.test(pin)) { err("Bitte die 4–6-stellige App-PIN eingeben."); return; }
    busy(true); $("pin-btn").textContent = "Entsperre …";
    try { var dkRaw = await dkFromPin(pin); $("pin").value = ""; start(await openWith(dkRaw), dkRaw); }
    catch (e) {
      busy(false); $("pin-btn").textContent = "Mit PIN entsperren"; $("pin").value = "";
      var m = e && e.message || "";
      if (m.indexOf("wrongpin:") === 0) { var left = +m.split(":")[1]; err("PIN falsch. Noch " + left + (left === 1 ? " Versuch" : " Versuche") + ", danach nur noch mit Passwort."); $("pin").classList.add("bad"); $("pin").focus(); }
      else if (m === "keyid") { removePin(); $("pane-pin").hidden = true; err("Die App-PIN passt nicht mehr zum aktuellen Schlüssel. Bitte mit Passwort entsperren und die PIN neu festlegen."); }
      else { $("pane-pin").hidden = true; err(m === "locked" ? "Zu viele Fehlversuche – die App-PIN wurde gelöscht. Bitte mit Passwort entsperren." : "App-PIN nicht mehr verfügbar. Bitte mit Passwort entsperren."); }
    }
  }
  async function init() {
    $("pw").addEventListener("input", function () { this.classList.remove("bad"); err(""); });
    $("pw-form").addEventListener("submit", onPassword);
    $("pin-form").addEventListener("submit", onPin);
    $("pin").addEventListener("input", function () { this.classList.remove("bad"); });
    if (!subtle) { err("Dieser Browser unterstützt keine sichere Entschlüsselung (WebCrypto fehlt)."); busy(true); return; }
    try { await loadVault(); } catch (e) { err(e.message); busy(true); return; }
    // Angemeldet bleiben: gespeicherten Datenschlüssel versuchen
    var rem = null; try { rem = JSON.parse(ls(K_REMEMBER) || "null"); } catch (e) { rem = null; }
    if (rem && rem.id === vault.keyId) {
      try { var raw = unb64(rem.k); start(await openWith(raw), raw); return; } catch (e) { ls(K_REMEMBER, null); }
    } else if (rem) { ls(K_REMEMBER, null); }
    var fr = faceRec();
    if (fr && fr.keyId !== vault.keyId) { ls(K_FACE, null); fr = null; }
    var pr = pinRec();
    if (pr && pr.keyId !== vault.keyId) { ls(K_PIN, null); pr = null; }
    if (pr) {
      $("pane-pin").hidden = false; $("remember").checked = false;
      $("lock-sub").textContent = fr ? "Mit Face ID, App-PIN oder Passwort entsperren." : "Mit App-PIN oder Passwort entsperren.";
    }
    if (fr && faceCapableSync()) {
      $("pane-face").hidden = false; $("face-btn").onclick = onFace;
      $("remember").checked = false;                 // bei aktivem Face ID standardmäßig aus
      if (!pr) $("lock-sub").textContent = "Mit Face ID oder Passwort entsperren.";
      $("note").textContent = CODE_HINT;
    } else if (!pr) { $("pw").focus(); }
  }
  init();
})();
