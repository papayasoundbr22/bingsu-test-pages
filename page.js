/* Share page player. No outside requests; see docs/share-templates.md. */
(function () {
  'use strict';

  /* bingsu.e2e/1 (docs/design/agent-share.md section 3) with WebCrypto, byte
     for byte as the Swift ShareCrypto does it and as the shared vectors
     (share-e2e-v1.json) check. Keys stay in memory; nothing here logs,
     stores or sends one. */
  var e2e = (function () {
    var LABEL = 'bingsu/share/v1', CLI = 'bingsu', SIGNATURE = 'share.sig.json';
    var subtle = typeof crypto !== 'undefined' ? crypto.subtle : undefined;
    var encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
    function utf8(s) { return encoder.encode(s); }
    function text(bytes) { return decoder.decode(bytes); }
    function join() {
      var parts = Array.prototype.slice.call(arguments), size = 0, at = 0;
      parts.forEach(function (p) { size += p.length; });
      var out = new Uint8Array(size);
      parts.forEach(function (p) { out.set(p, at); at += p.length; });
      return out;
    }
    function fail(code, detail) { var e = new Error(code); e.code = code; e.detail = detail; return e; }
    function bits(promise) { return promise.then(function (b) { return new Uint8Array(b); }); }

    function b64u(bytes) {
      var s = '';
      for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, '-').split('/').join('_').replace(/=+$/, '');
    }
    /* No padding, no other alphabet, no stray low bits: one spelling per value. */
    function unb64u(s) {
      if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
      var bin;
      try { bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - s.length % 4) % 4)); } catch (e) { return null; }
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return b64u(out) === s ? out : null;
    }
    function hex(bytes) { return Array.prototype.map.call(bytes, function (b) { return (b < 16 ? '0' : '') + b.toString(16); }).join(''); }
    function base32(bytes) {
      var alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ', out = '', buffer = 0, count = 0;
      for (var i = 0; i < bytes.length; i++) {
        buffer = (buffer << 8) | bytes[i];
        count += 8;
        while (count >= 5) { count -= 5; out += alphabet[(buffer >> count) & 31]; }
        buffer &= (1 << count) - 1;
      }
      return count ? out + alphabet[(buffer << (5 - count)) & 31] : out;
    }
    function isShareId(s) { return typeof s === 'string' && /^[0-9a-hjkmnp-tv-z]{26}$/.test(s); }
    function isSharePath(p) {
      return typeof p === 'string' && /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,200}$/.test(p) && p.indexOf('//') < 0 && p.split('/').indexOf('..') < 0;
    }
    /* NFKC; White_Space, '-', U+2010 to U+2015 and U+2212 removed; ASCII
       upper-cased; then O as 0 and I and L as 1, as Crockford reads them. */
    function normalizePasscode(raw) {
      return Array.from(String(raw).normalize('NFKC')).map(function (ch) {
        var v = ch.codePointAt(0);
        if (/\p{White_Space}/u.test(ch) || v === 0x2D || (v >= 0x2010 && v <= 0x2015) || v === 0x2212) return '';
        if (v >= 0x61 && v <= 0x7A) ch = String.fromCharCode(v - 32);
        return ch === 'O' ? '0' : ch === 'I' || ch === 'L' ? '1' : ch;
      }).join('');
    }

    /* `ikm` is bytes, or a key already imported for HKDF (the content key). */
    function hkdf(ikm, salt, info) {
      var key = ikm instanceof Uint8Array ? subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']) : Promise.resolve(ikm);
      return bits(key.then(function (k) { return subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: info }, k, 256); }));
    }
    function hmac(key, message) {
      return bits(subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
        .then(function (k) { return subtle.sign('HMAC', k, message); }));
    }
    function sha256(data) { return bits(subtle.digest('SHA-256', data)); }
    function mode(passcode, gated) { return 'p=' + (passcode ? 1 : 0) + ';g=' + (gated ? 1 : 0); }
    /* P = PBKDF2-HMAC-SHA256(passcode, "…passcode:" || id, 600000, 32 bytes). */
    function passcodeKey(normalized, id) {
      return bits(subtle.importKey('raw', utf8(normalized), 'PBKDF2', false, ['deriveBits']).then(function (k) {
        return subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: utf8(LABEL + ' passcode:' + id), iterations: 600000 }, k, 256);
      }));
    }
    /* C = HKDF(L || P || G, id, "…content;" || mode); P and G only when set. */
    function contentKey(id, link, passcode, gate) {
      var none = new Uint8Array(0);
      return hkdf(join(link, passcode || none, gate || none), utf8(id), utf8(LABEL + ' content;' + mode(!!passcode, !!gate)));
    }
    function fileKey(content, id, path) { return hkdf(content, utf8(id), utf8(LABEL + ' file:' + path)); }
    /* The relay origin proof and cap bind, as a browser's URL.origin writes it. */
    function relayOrigin(raw) {
      var u = new URL(String(raw).trim());
      if (u.protocol !== 'https:' || u.username || u.password || !u.hostname) throw fail('relay');
      return u.origin;
    }
    function proof(link, id, origin) {
      return hkdf(link, utf8(id), utf8(LABEL + ' link-proof')).then(function (k) { return hmac(k, utf8(id + '|' + origin)); }).then(b64u);
    }
    function cap(k0, id, m, origin) {
      return hkdf(k0, utf8(id), utf8(LABEL + ' cap;' + m)).then(function (k) { return hmac(k, utf8(id + '|' + origin)); }).then(b64u);
    }

    /* P.bse = "BSE1" || nonce || AES-256-GCM(F(P), nonce, plaintext, aad = "…|" || id || "|" || P).
       A file that does not open is an error, never shown in part. */
    function openFile(content, id, path, sealed) {
      var b = new Uint8Array(sealed);
      if (!isSharePath(path) || b.length < 32 || String.fromCharCode(b[0], b[1], b[2], b[3]) !== 'BSE1') return Promise.reject(fail('damaged', path));
      return bits(fileKey(content, id, path)
        .then(function (k) { return subtle.importKey('raw', k, 'AES-GCM', false, ['decrypt']); })
        .then(function (k) { return subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(4, 16), additionalData: utf8(LABEL + '|' + id + '|' + path) }, k, b.subarray(16)); }))
        .catch(function () { throw fail('damaged', path); });
    }

    /* An X25519 sealed box (replies, design section 4): a fresh key pair,
       W = HKDF(X25519(e, R), e.public || R, info), then AES-256-GCM. `fixed`
       ({ ephemeral, nonce }) replays the vectors. */
    var X25519 = { name: 'X25519' }, PKCS8_X25519 = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32];
    async function sealBox(plaintext, recipient, info, aad, fixed) {
      var pair;
      if (fixed) {
        var own = await subtle.importKey('pkcs8', join(new Uint8Array(PKCS8_X25519), fixed.ephemeral), X25519, true, ['deriveBits']);
        pair = { privateKey: own, publicKey: unb64u((await subtle.exportKey('jwk', own)).x) };
      } else {
        var made = await subtle.generateKey(X25519, false, ['deriveBits']);
        pair = { privateKey: made.privateKey, publicKey: new Uint8Array(await subtle.exportKey('raw', made.publicKey)) };
      }
      var theirs = await subtle.importKey('raw', recipient, X25519, false, []);
      var secret = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: theirs }, pair.privateKey, 256));
      if (secret.every(function (b) { return b === 0; })) throw fail('weak_key');
      var w = await subtle.importKey('raw', await hkdf(secret, join(pair.publicKey, recipient), utf8(info)), 'AES-GCM', false, ['encrypt']);
      var nonce = fixed ? fixed.nonce : crypto.getRandomValues(new Uint8Array(12));
      var ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, w, plaintext));
      return { epk: b64u(pair.publicKey), ct: b64u(join(nonce, ct)) };
    }

    function hash(data) { return sha256(data).then(function (h) { return 'sha256:' + hex(h); }); }
    function fingerprint(key) { return sha256(key).then(function (h) { return base32(h.subarray(0, 10)).match(/.{1,4}/g).join('-'); }); }
    function json(bytes) { try { return JSON.parse(text(bytes)); } catch (e) { return null; } }

    /* share.sig.json (design section 2): Ed25519 over the manifest's exact
       bytes, then the manifest names this share and the key that signed.
       `valid` only when that key is the one the link names (`pin`, its
       fingerprint without dashes): anyone can sign, so a good signature by
       any other key is `unknown`, and `other` when the link named a key.
       `unchecked` when this browser has no Ed25519. */
    async function verifySignature(bytes, id, pin) {
      var file = json(bytes), out = { state: 'invalid' };
      if (!file || file.schema !== CLI + '.signature/1' || file.alg !== 'Ed25519' || typeof file.key !== 'string' || file.key.indexOf('ed25519:') !== 0) return out;
      var key = unb64u(file.key.slice(8)), manifest = unb64u(file.manifest), sig = unb64u(file.sig);
      if (!key || key.length !== 32 || !manifest || !sig || sig.length !== 64) return out;
      out.key = file.key;
      out.fingerprint = await fingerprint(key);
      var ok;
      try {
        var k = await subtle.importKey('raw', key, { name: 'Ed25519' }, false, ['verify']);
        ok = await subtle.verify({ name: 'Ed25519' }, k, sig, join(utf8(LABEL + ' manifest\n'), manifest));
      } catch (e) { out.state = 'unchecked'; return out; }
      var m = json(manifest);
      if (!ok || !m || m.schema !== CLI + '.manifest/1') return out;
      out.manifest = m;
      out.name = m.sender && typeof m.sender.name === 'string' ? m.sender.name : null;
      if (m.sender && m.sender.key === file.key && m.shareId === id) {
        out.state = !pin ? 'unknown' : pin === out.fingerprint.replace(/-/g, '') ? 'valid' : 'other';
      }
      return out;
    }

    /* The clear agent.json: only its id and flags are used. */
    function readStub(stub) {
      var s = stub && stub.share;
      if (!s || s.encrypted !== true || !isShareId(s.id)) throw fail('not_share');
      return { id: s.id, passcode: s.passcode === true, gate: typeof s.gate === 'string' ? s.gate : null,
               recipientBound: s.recipientBound === true, expiresAt: typeof s.expiresAt === 'string' ? s.expiresAt : null };
    }
    /* The `k` of `#k=…&…`: the first part that is a 32-byte key. */
    function linkKey(fragment) {
      var parts = String(fragment).replace(/^#/, '').split('&');
      for (var i = 0; i < parts.length; i++) {
        var k = parts[i].indexOf('k=') === 0 ? unb64u(parts[i].slice(2)) : null;
        if (k && k.length === 32) return k;
      }
      return null;
    }
    /* The `s` of `#k=…&s=…`: the signer's fingerprint, upper-cased, without dashes. */
    function signerPin(fragment) {
      var parts = String(fragment).replace(/^#/, '').split('&');
      for (var i = 0; i < parts.length; i++) {
        var s = parts[i].indexOf('s=') === 0 ? parts[i].slice(2).replace(/-/g, '').toUpperCase() : '';
        if (/^[0-9A-HJKMNP-TV-Z]{16}$/.test(s)) return s;
      }
      return null;
    }
    /* The content key as a key that can only derive file keys. */
    async function keys(stub, link, passcode) {
      var p = passcode != null ? await passcodeKey(normalizePasscode(passcode), stub.id) : null;
      var c = await contentKey(stub.id, link, p, null);
      if (p) p.fill(0);
      var content = await subtle.importKey('raw', c, 'HKDF', false, ['deriveBits']);
      c.fill(0);
      return { id: stub.id, content: content };
    }
    function date(s) { var t = typeof s === 'string' ? Date.parse(s) : NaN; return isNaN(t) ? null : new Date(t); }

    /* With a valid signature every file must be one the manifest lists, with
       its hash: the link opens files sealed by anyone holding it, the
       signature names the sender's. Without one there is nothing to check. */
    async function checked(files, path, bytes) {
      if (files && (!Object.prototype.hasOwnProperty.call(files, path) || files[path] !== await hash(bytes))) throw fail('signature', path);
      return bytes;
    }
    /* `get(path)` gives P.bse's bytes, or null; this gives the file, opened and checked. */
    function reader(get, k, files) {
      return function (path) {
        return Promise.resolve(get(path)).then(function (b) {
          if (!b) throw fail('damaged', path);
          return openFile(k.content, k.id, path, b);
        }).then(function (plain) { return checked(files, path, plain); });
      };
    }

    /* page.json first, so a wrong link or passcode fails there; then the
       body and the signature. `clear(path)` gives a published file's bytes,
       or null: the shell the signature lists must be what the host serves. */
    async function open(get, k, now, pin, clear) {
      var sealedPage = await get('page.json'), pageBytes;
      try { pageBytes = await openFile(k.content, k.id, 'page.json', sealedPage || new Uint8Array(0)); } catch (e) { throw fail('locked'); }
      var page = json(pageBytes);
      if (!page || typeof page.title !== 'string') throw fail('damaged', 'page.json');
      var inner = date(page.expiresAt);
      if (inner && inner <= now) throw fail('expired', inner);
      var sealedBody = await get('content.html');
      if (!sealedBody) throw fail('damaged', 'content.html');
      var body = await openFile(k.content, k.id, 'content.html', sealedBody);
      var signature = { state: 'missing' }, sealedSig = await get(SIGNATURE), files = null;
      // A link that names a signer refuses a share without that signature: removing it is not a way around the pin.
      if (!sealedSig && pin) throw fail('signature', signature);
      // Unpinned: nothing signs without adding the pin, so the signature is the folder maker's and is never parsed.
      if (sealedSig && pin) {
        signature = await verifySignature(await openFile(k.content, k.id, SIGNATURE, sealedSig), k.id, pin);
        if (signature.state === 'invalid' || signature.state === 'other') throw fail('signature', signature);
        if (signature.state === 'valid' || signature.state === 'unknown') {
          files = signature.manifest.files && typeof signature.manifest.files === 'object' ? signature.manifest.files : {};
          await checked(files, 'page.json', pageBytes);
          await checked(files, 'content.html', body);
          var shell = signature.manifest.shell;
          // shortcut: a host that swaps page.js itself is not caught here (it runs instead); `bingsu open` checks it natively.
          if (shell && typeof shell === 'object' && clear) {
            for (var path in shell) {
              if (!isSharePath(path)) throw fail('signature', path);
              var bytes = await clear(path);
              if (!bytes) throw fail('signature', path);
              await checked(shell, path, bytes);
            }
          }
        }
      }
      // Only sealed or signed copies count: the clear stub's expiry is the host's to change.
      var expiry = (signature.manifest && date(signature.manifest.expiresAt)) || inner;
      if (expiry && expiry <= now) throw fail('expired', expiry);
      return { page: page, html: text(body), signature: signature, expiresAt: expiry, file: reader(get, k, files) };
    }

    /* A plain share whose link names a signer (`#s=`): share.sig.json must
       hold by that key, for the id in page.json, and list page.json as it is
       here. `get(path)` gives a file's bytes, or null. */
    async function checkPlain(get, pin) {
      var pageBytes = await get('page.json'), sig = await get(SIGNATURE), page = pageBytes && json(pageBytes);
      if (!sig || !page) throw fail('signature');
      var s = await verifySignature(sig, page.shareId, pin);
      if (s.state === 'unchecked') return s;
      if (s.state !== 'valid' || s.manifest.shell) throw fail('signature', s);
      var files = s.manifest.files && typeof s.manifest.files === 'object' ? s.manifest.files : {};
      await checked(files, 'page.json', pageBytes);
      // Everything the page shows, this HTML included; the video streams unchecked (an encrypted share checks it).
      for (var path in files) {
        if (path === 'page.json' || path === SIGNATURE || /^video(\/|\.mp4$)/.test(path)) continue;
        if (!isSharePath(path)) throw fail('signature', path);
        var bytes = await get(path);
        if (!bytes) throw fail('signature', path);
        await checked(files, path, bytes);
      }
      return s;
    }

    /* The line under the title. A signature this browser cannot check names nobody. */
    function provenance(s, plain) {
      var head = plain ? '' : 'End-to-end encrypted. ';
      var agent = s.manifest && s.manifest.madeBy && s.manifest.madeBy.agent;
      var by = typeof agent === 'string' && agent ? ', made by the agent ' + agent.slice(0, 60) : '';
      if (s.state === 'valid') return { text: head + (s.name ? 'Signed by ' + s.name : 'Signed') + by, fingerprint: s.fingerprint };
      if (s.state === 'unknown') return { text: head + 'Signed by a key the link does not name, so nothing proves who sent it.', fingerprint: null };
      if (s.state === 'unchecked') return { text: head + 'Signature not checked in this browser.', fingerprint: null };
      return { text: head + 'Not signed.', fingerprint: null };
    }
    /* Element ids: only the ones the built-in renderer writes, so a body
       cannot take the name of something the page looks up. */
    var IDS = ['notes-heading'];
    function safeId(v) { return IDS.indexOf(v) >= 0; }

    return { label: LABEL, b64u: b64u, unb64u: unb64u, hex: hex, base32: base32, isShareId: isShareId, isSharePath: isSharePath,
             normalizePasscode: normalizePasscode, passcodeKey: passcodeKey, mode: mode, contentKey: contentKey, fileKey: fileKey,
             relayOrigin: relayOrigin, proof: proof, cap: cap, openFile: openFile, sealBox: sealBox, hash: hash,
             fingerprint: fingerprint, verifySignature: verifySignature, readStub: readStub, linkKey: linkKey, signerPin: signerPin, keys: keys,
             open: open, checkPlain: checkPlain, reader: reader, provenance: provenance, safeId: safeId, text: text, supported: !!subtle };
  })();
  /* Outside a browser (the tests run this file in Node) only the crypto is wanted. */
  if (typeof document === 'undefined') { globalThis.BingsuPlayer = { e2e: e2e }; return; }

  var root = document.documentElement;
  var THEME_KEY = 'share-theme';
  /* Dark or light when the viewer chose one; otherwise the system's. */
  function savedTheme() { try { return localStorage.getItem(THEME_KEY); } catch (e) { return null; } }
  function applyTheme(choice) {
    if (choice === 'light' || choice === 'dark') root.setAttribute('data-theme', choice); else root.removeAttribute('data-theme');
  }
  applyTheme(savedTheme());
  var here = (document.currentScript && document.currentScript.src) || '';
  var folder = here.replace(/[^\/]*$/, '');
  var isFile = location.protocol === 'file:';
  /* A one-file share (ShareSingleFile): its sealed files, stub and link travel inside the page. */
  var INLINE = (function () { var el = document.getElementById('bingsu-inline'); try { return el && JSON.parse(el.textContent); } catch (e) { return null; } })();
  function inlineBytes(b64) { var s = atob(b64), out = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
  var reduceMotion = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  var RATES = [1, 1.25, 1.5, 2];
  var ICONS = {
    play: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5.14v13.72a1 1 0 0 0 1.52.85l10.6-6.86a1 1 0 0 0 0-1.7L9.52 4.29A1 1 0 0 0 8 5.14z"/></svg>',
    pause: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6.5" y="5" width="4" height="14" rx="1.2"/><rect x="13.5" y="5" width="4" height="14" rx="1.2"/></svg>',
    sound: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9.5h3.5L12 5.5v13l-4.5-4H4z"/><path d="M15.5 9a4 4 0 0 1 0 6M18 6.5a7.5 7.5 0 0 1 0 11" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    muted: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9.5h3.5L12 5.5v13l-4.5-4H4z"/><path d="M16 9.5l5 5M21 9.5l-5 5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    captions: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5.5" width="18" height="13" rx="2.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M10.5 10.2a2.2 2.2 0 1 0 0 3.6M16.5 10.2a2.2 2.2 0 1 0 0 3.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    full: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9V5.5A1.5 1.5 0 0 1 5.5 4H9M15 4h3.5A1.5 1.5 0 0 1 20 5.5V9M20 15v3.5a1.5 1.5 0 0 1-1.5 1.5H15M9 20H5.5A1.5 1.5 0 0 1 4 18.5V15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    exitFull: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 4v3.5A1.5 1.5 0 0 1 7.5 9H4M20 9h-3.5A1.5 1.5 0 0 1 15 7.5V4M15 20v-3.5a1.5 1.5 0 0 1 1.5-1.5H20M4 15h3.5A1.5 1.5 0 0 1 9 16.5V20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>'
  };

  function clock(t) {
    t = Math.max(0, Math.floor(t || 0));
    var h = Math.floor(t / 3600), m = Math.floor(t % 3600 / 60), s = t % 60;
    return (h ? h + ':' + (m < 10 ? '0' : '') + m : m) + ':' + (s < 10 ? '0' : '') + s;
  }
  function make(tag, cls, parent) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (parent) parent.appendChild(e);
    return e;
  }
  function button(cls, label, icon, parent) {
    var b = make('button', 'player-button ' + cls, parent);
    b.type = 'button';
    b.setAttribute('aria-label', label);
    b.title = label;
    if (icon) b.innerHTML = icon;
    return b;
  }
  function typing(target) {
    var tag = target && target.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (target && target.isContentEditable);
  }

  /* WebVTT text to cues (enough for the captions share pages carry). */
  function parseVTT(text) {
    var cues = [];
    text.replace(/\r/g, '').split(/\n\n+/).forEach(function (block) {
      var lines = block.split('\n');
      for (var i = 0; i < lines.length; i++) {
        var m = lines[i].match(/(\d+:)?(\d+):(\d+)\.(\d+)\s+-->\s+(\d+:)?(\d+):(\d+)\.(\d+)/);
        if (!m) continue;
        var at = function (h, mi, s, ms) { return (h ? parseInt(h, 10) * 3600 : 0) + parseInt(mi, 10) * 60 + parseInt(s, 10) + parseInt(ms, 10) / 1000; };
        /* DOMParser is inert: a caption cannot load an image or run a handler. */
        var body = new DOMParser().parseFromString(lines.slice(i + 1).join('\n'), 'text/html').body;
        cues.push({ start: at(m[1], m[2], m[3], m[4]), end: at(m[5], m[6], m[7], m[8]), text: body.textContent });
        break;
      }
    });
    return cues;
  }
  function cuesFromPage() {
    var lines = document.querySelectorAll('[data-transcript] [data-start]');
    return Array.prototype.map.call(lines, function (b) {
      var text = b.querySelector('.transcript-text');
      return { start: parseFloat(b.getAttribute('data-start')), end: parseFloat(b.getAttribute('data-end') || 'NaN'), text: (text || b).textContent };
    });
  }

  var players = [];
  var active = null;

  function mount(box, options) {
    if (!box || box.__player) return box && box.__player;
    var o = options || {};
    var d = box.dataset;
    var cfg = {
      playlist: o.playlist || d.playlist,
      mp4: o.mp4 || d.mp4,
      poster: o.poster || d.poster,
      captions: o.captions || d.captions,
      transcript: o.transcript,
      title: o.title || d.title || document.title,
      author: o.author || d.author,
      duration: parseFloat(o.duration || d.duration) || 0
    };
    box.classList.add('player');
    var video = box.querySelector('video');
    if (!video) {
      video = make('video', 'player-video', box);
      video.setAttribute('playsinline', '');
      video.preload = 'metadata';
    }
    // An encrypted share's poster and captions are decrypted into blob: addresses.
    if (sealed && cfg.poster) sealed.url(cfg.poster).then(function (u) { if (!unplayable()) { cfg.poster = u; video.poster = u; } }, function () {});
    else if (cfg.poster) video.poster = cfg.poster;
    video.controls = false;

    var big = button('player-big-play', 'Play', ICONS.play, box);
    var caps = make('div', 'player-captions', box);
    caps.setAttribute('aria-hidden', 'true');
    var message = make('div', 'player-message', box);
    message.hidden = true;
    var bar = make('div', 'player-controls', box);
    var scrub = make('div', 'player-scrub', bar);
    scrub.tabIndex = 0;
    scrub.setAttribute('role', 'slider');
    scrub.setAttribute('aria-label', 'Seek');
    scrub.setAttribute('aria-valuemin', '0');
    var track = make('div', 'player-scrub-track', scrub);
    var buffered = make('div', 'player-scrub-buffered', track);
    var played = make('div', 'player-scrub-played', track);
    var thumb = make('div', 'player-scrub-thumb', track);
    var tip = make('div', 'player-scrub-tip', scrub);
    var chapters = (o.chapters || Array.prototype.map.call(document.querySelectorAll('[data-chapters] [data-start]'), function (b) {
      var t = b.querySelector('.chapter-title');
      return { start: parseFloat(b.getAttribute('data-start')), title: (t || b).textContent };
    })).filter(function (c) { return isFinite(c.start); }).sort(function (a, b) { return a.start - b.start; });
    function chapterAt(t) {
      for (var i = chapters.length - 1; i >= 0; i--) if (chapters[i].start <= t) return chapters[i];
      return null;
    }
    var marks = [];
    function placeMarks() {
      var end = duration();
      Array.prototype.forEach.call(track.querySelectorAll('.player-scrub-note'), function (t) { t.remove(); });
      if (!end) return;
      marks.forEach(function (at) { make('div', 'player-scrub-note', track).style.left = (Math.min(at, end) / end * 100) + '%'; });
    }
    function placeTicks() {
      var end = duration();
      Array.prototype.forEach.call(track.querySelectorAll('.player-scrub-tick'), function (t) { t.remove(); });
      if (!end) return;
      chapters.forEach(function (c) {
        if (c.start <= 0 || c.start >= end) return;
        make('div', 'player-scrub-tick', track).style.left = (c.start / end * 100) + '%';
      });
    }
    var row = make('div', 'player-row', bar);
    var playBtn = button('player-play', 'Play', ICONS.play, row);
    var muteBtn = button('player-mute', 'Mute', ICONS.sound, row);
    var time = make('span', 'player-time', row);
    make('span', 'player-spacer', row);
    var speedBtn = button('player-speed', 'Playback speed', null, row);
    speedBtn.textContent = '1×';
    var capsBtn = button('player-captions-toggle', 'Captions', ICONS.captions, row);
    capsBtn.setAttribute('aria-pressed', 'false');
    capsBtn.hidden = true;
    var fullBtn = button('player-fullscreen', 'Full screen', ICONS.full, row);

    var hls = null, started = false, cues = [], captionsOn = false, dragging = false, idleTimer = 0;
    function duration() { return isFinite(video.duration) && video.duration > 0 ? video.duration : cfg.duration; }
    function show(text, art) { message.textContent = text; message.hidden = !text; if (art) message.setAttribute('data-art', art); else message.removeAttribute('data-art'); }

    function useFile(src) { video.src = src; }
    /* A one-file share too big for its video keeps the poster and links to the full share. */
    function linkFull() {
      if (typeof INLINE.full !== 'string' || INLINE.full.indexOf('https:') !== 0) return cannotPlay();
      box.classList.add('is-unplayable');
      var a = make('a', 'share-full', box);
      a.href = INLINE.full;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'Watch the full video';
    }
    function unplayable() { return box.classList.contains('is-unplayable'); }
    /* No still to click on and no controls: nothing here can play it. Notes listen for the event. */
    function cannotPlay() {
      cfg.poster = null;
      video.removeAttribute('poster');
      box.classList.add('is-unplayable');
      show('This browser cannot play encrypted video. Open the link in a current Safari, Chrome or Firefox.', 'bingsu');
      box.dispatchEvent(new Event('unplayable'));
    }
    function fallback() {
      if (hls) { hls.destroy(); hls = null; }
      if (cfg.mp4 && !sealed) { useFile(cfg.mp4); if (started) video.play().catch(function () {}); }
      else show(sealed ? 'This video could not be played.' : 'This browser cannot play this video.', 'bingsu');
    }
    function startHls() {
      // A page element named Hls would otherwise stand in for the library.
      if (typeof window.Hls !== 'function' || !window.Hls.isSupported()) return sealed ? cannotPlay() : fallback();
      var Hls = window.Hls;
      hls = new Hls(sealed ? { autoStartLoad: false, loader: SealedLoader } : { autoStartLoad: false });
      var tried = [];
      // Same picture in every level: pick by codec, HEVC when this browser
      // plays it (smaller), never switching while it plays.
      function pick() {
        var best = -1;
        hls.levels.forEach(function (l, i) {
          if (tried.indexOf(i) >= 0) return;
          if (best < 0 || /^hvc1|^hev1/.test(l.videoCodec || '')) best = i;
        });
        return best;
      }
      hls.on(Hls.Events.MANIFEST_PARSED, function () { var i = pick(); tried.push(i); hls.currentLevel = i; });
      hls.on(Hls.Events.ERROR, function (event, data) {
        if (!data.fatal) return;
        var next = pick();
        if (next >= 0 && data.type === Hls.ErrorTypes.MEDIA_ERROR) {
          tried.push(next);
          hls.recoverMediaError();
          hls.currentLevel = next;
          return;
        }
        fallback();
      });
      hls.loadSource(cfg.playlist);
      hls.attachMedia(video);
      if (started) hls.startLoad();
    }
    // Apple's own HLS player (Safari, every iPhone browser) handles HEVC
    // and separate sound best; elsewhere hls.js does, even where the
    // browser claims HLS support.
    var appleHLS = /Apple/.test(navigator.vendor || '');
    function loadHls() {
      if (typeof window.Hls === 'function') return startHls();
      var s = document.createElement('script');
      s.src = folder + 'hls.min.js';
      s.onload = startHls;
      s.onerror = fallback;
      document.head.appendChild(s);
    }
    function attach() {
      // Encrypted: only hls.js can hand the player decrypted pieces; native HLS never sees them.
      if (sealed) {
        if (INLINE && INLINE.full) return linkFull();
        if (!cfg.playlist || !(window.MediaSource || window.ManagedMediaSource)) return cannotPlay();
        // AirPlay would fetch the sealed files itself; Managed Media Source needs it off.
        video.disableRemotePlayback = true;
        return loadHls();
      }
      if (isFile && cfg.mp4) return useFile(cfg.mp4);
      if (cfg.playlist && appleHLS && video.canPlayType('application/vnd.apple.mpegurl')) return useFile(cfg.playlist);
      if (cfg.playlist && !isFile && (window.MediaSource || window.ManagedMediaSource)) return loadHls();
      if (cfg.playlist && video.canPlayType('application/vnd.apple.mpegurl')) return useFile(cfg.playlist);
      if (cfg.mp4) return useFile(cfg.mp4);
      if (isFile) show('This video plays once the folder is published, or here in Safari.', 'bingsu'); else show('This browser cannot play this video.', 'bingsu');
    }

    function play() {
      if (!started) { started = true; box.classList.add('is-started'); if (hls) hls.startLoad(); }
      var p = video.play();
      if (p && p.catch) p.catch(function () {});
    }
    function pause() { video.pause(); }
    function toggle() { if (video.paused || video.ended) play(); else pause(); }
    function seek(t) {
      var end = duration();
      video.currentTime = Math.max(0, end ? Math.min(t, end - 0.05) : t);
      paint();
    }
    function setRate(r) { video.playbackRate = r; speedBtn.textContent = r + '×'; speedBtn.setAttribute('aria-label', 'Playback speed ' + r + '×'); }
    function setCaptions(on) {
      captionsOn = on && cues.length > 0;
      capsBtn.setAttribute('aria-pressed', String(captionsOn));
      box.classList.toggle('has-captions-on', captionsOn);
      paintCaptions();
    }
    function fullscreenElement() { return document.fullscreenElement || document.webkitFullscreenElement; }
    function toggleFullscreen() {
      if (fullscreenElement()) (document.exitFullscreen || document.webkitExitFullscreen).call(document);
      else if (box.requestFullscreen) box.requestFullscreen();
      else if (box.webkitRequestFullscreen) box.webkitRequestFullscreen();
      else if (video.webkitEnterFullscreen) video.webkitEnterFullscreen();
    }

    function paint() {
      var end = duration(), now = video.currentTime || 0, f = end ? Math.min(1, now / end) : 0;
      played.style.width = (f * 100) + '%';
      thumb.style.left = (f * 100) + '%';
      // The page's own length, so the player and the title agree (the stream
      // can end a frame early); at the end the elapsed time reads the same.
      var total = cfg.duration || end, shown = video.ended ? total : now;
      time.textContent = clock(shown) + ' / ' + clock(total);
      scrub.setAttribute('aria-valuemax', String(Math.round(total)));
      scrub.setAttribute('aria-valuenow', String(Math.round(shown)));
      scrub.setAttribute('aria-valuetext', clock(shown) + ' of ' + clock(total));
      paintCaptions();
    }
    function paintBuffered() {
      var end = duration(), b = video.buffered;
      if (!end || !b.length) return;
      buffered.style.width = Math.min(100, b.end(b.length - 1) / end * 100) + '%';
    }
    function cueAt(t) {
      for (var i = cues.length - 1; i >= 0; i--) {
        var c = cues[i];
        if (c.start <= t) return (isNaN(c.end) || t < c.end + 0.3) ? c : null;
      }
      return null;
    }
    function paintCaptions() {
      var c = captionsOn ? cueAt(video.currentTime || 0) : null;
      var text = c ? c.text : '';
      if (caps.textContent !== text) caps.textContent = text;
      caps.hidden = !text;
    }
    function paintPlaying() {
      var playing = !video.paused && !video.ended;
      box.classList.toggle('is-playing', playing);
      playBtn.innerHTML = playing ? ICONS.pause : ICONS.play;
      playBtn.setAttribute('aria-label', playing ? 'Pause' : 'Play');
      playBtn.title = playing ? 'Pause' : 'Play';
      wake();
    }
    function paintMuted() {
      muteBtn.innerHTML = video.muted ? ICONS.muted : ICONS.sound;
      muteBtn.setAttribute('aria-label', video.muted ? 'Unmute' : 'Mute');
      muteBtn.title = video.muted ? 'Unmute' : 'Mute';
    }
    function wake() {
      box.classList.remove('is-idle');
      clearTimeout(idleTimer);
      if (!video.paused) idleTimer = setTimeout(function () { if (!dragging) box.classList.add('is-idle'); }, 2500);
    }

    function fraction(e) {
      var r = track.getBoundingClientRect();
      return Math.max(0, Math.min(1, (e.clientX - r.left) / (r.width || 1)));
    }
    scrub.addEventListener('pointerdown', function (e) {
      dragging = true;
      scrub.setPointerCapture(e.pointerId);
      box.classList.add('is-scrubbing');
      seek(fraction(e) * duration());
    });
    scrub.addEventListener('pointermove', function (e) {
      var f = fraction(e);
      var chapter = chapterAt(f * duration());
      tip.textContent = clock(f * duration()) + (chapter ? '  ' + chapter.title : '');
      tip.style.left = (f * 100) + '%';
      if (dragging) seek(f * duration());
    });
    function endDrag() { dragging = false; box.classList.remove('is-scrubbing'); wake(); }
    scrub.addEventListener('pointerup', endDrag);
    scrub.addEventListener('pointercancel', endDrag);
    scrub.addEventListener('keydown', function (e) {
      var step = { ArrowLeft: -5, ArrowRight: 5, ArrowDown: -5, ArrowUp: 5, PageDown: -duration() / 10, PageUp: duration() / 10 }[e.key];
      if (e.key === 'Home') seek(0); else if (e.key === 'End') seek(duration()); else if (step) seek(video.currentTime + step); else return;
      e.preventDefault();
      e.stopPropagation();
    });

    big.addEventListener('click', play);
    playBtn.addEventListener('click', toggle);
    muteBtn.addEventListener('click', function () { video.muted = !video.muted; });
    speedBtn.addEventListener('click', function () { setRate(RATES[(RATES.indexOf(video.playbackRate) + 1) % RATES.length]); });
    capsBtn.addEventListener('click', function () { setCaptions(!captionsOn); });
    fullBtn.addEventListener('click', toggleFullscreen);
    video.addEventListener('click', function (e) {
      if (e.pointerType === 'touch' && box.classList.contains('is-idle')) return wake();
      toggle();
    });
    video.addEventListener('dblclick', toggleFullscreen);
    box.addEventListener('pointermove', wake);
    box.addEventListener('pointerdown', function () { active = api; });
    box.addEventListener('focusin', function () { active = api; wake(); });
    ['play', 'pause', 'ended'].forEach(function (n) { video.addEventListener(n, paintPlaying); });
    ['timeupdate', 'seeking', 'loadedmetadata', 'durationchange'].forEach(function (n) { video.addEventListener(n, paint); });
    video.addEventListener('progress', paintBuffered);
    video.addEventListener('loadedmetadata', placeTicks);
    video.addEventListener('loadedmetadata', placeMarks);
    video.addEventListener('volumechange', paintMuted);
    video.addEventListener('waiting', function () { box.classList.add('is-waiting'); });
    video.addEventListener('playing', function () { box.classList.remove('is-waiting'); show(''); });
    video.addEventListener('error', function () { if (!hls) { if (cfg.mp4 && video.currentSrc.indexOf(cfg.mp4) < 0) fallback(); else show('This video could not be played.', 'bingsu'); } });
    function onFullscreen() {
      var on = fullscreenElement() === box;
      box.classList.toggle('is-fullscreen', on);
      fullBtn.innerHTML = on ? ICONS.exitFull : ICONS.full;
      fullBtn.setAttribute('aria-label', on ? 'Exit full screen' : 'Full screen');
    }
    document.addEventListener('fullscreenchange', onFullscreen);
    document.addEventListener('webkitfullscreenchange', onFullscreen);
    // iPhone plays full screen in its own player: hand it the captions track.
    video.addEventListener('webkitbeginfullscreen', function () { if (video.textTracks[0]) video.textTracks[0].mode = captionsOn ? 'showing' : 'hidden'; });
    video.addEventListener('webkitendfullscreen', function () { if (video.textTracks[0]) video.textTracks[0].mode = 'hidden'; });
    // The captions track, for the iPhone's own full screen player (a page
    // opened from disk may not load it, so it is added only when published).
    if (cfg.captions && !isFile && !video.querySelector('track')) {
      var trackEl = make('track', '', video);
      trackEl.kind = 'captions';
      if (sealed) sealed.url(cfg.captions).then(function (u) { trackEl.src = u; }, function () {});
      else trackEl.src = cfg.captions;
      trackEl.srclang = root.lang || 'en';
      trackEl.label = 'Captions';
    }
    if (video.textTracks[0]) video.textTracks[0].mode = 'hidden';

    function useCues(list) {
      cues = (list || []).filter(function (c) { return isFinite(c.start) && c.text; });
      capsBtn.hidden = cues.length === 0;
      if (cues.length) startCaptions();
    }
    function startCaptions() {
      // On when no transcript is in view beside the video (phones), off when it is.
      var line = document.querySelector('[data-transcript]');
      var beside = line && line.getClientRects().length && line.getBoundingClientRect().left >= box.getBoundingClientRect().right - 1;
      setCaptions(!beside);
    }
    if (cfg.transcript) useCues(cfg.transcript);
    else if (document.querySelector('[data-transcript] [data-start]')) useCues(cuesFromPage());
    else if (cfg.captions && !isFile && window.fetch) {
      (sealed ? sealed.file(cfg.captions).then(e2e.text) : fetch(cfg.captions).then(function (r) { return r.ok ? r.text() : ''; }))
        .then(function (t) { useCues(parseVTT(t)); }).catch(function () {});
    }

    if ('mediaSession' in navigator && window.MediaMetadata) {
      video.addEventListener('play', function () {
        navigator.mediaSession.metadata = new MediaMetadata({ title: cfg.title, artist: cfg.author || '', artwork: cfg.poster && !isFile ? [{ src: new URL(cfg.poster, location.href).href }] : [] });
      });
    }

    var api = {
      element: box, video: video, play: play, pause: pause, seek: seek, toggle: toggle,
      setRate: setRate, setCaptions: function (on) { setCaptions(on); }, toggleCaptions: function () { setCaptions(!captionsOn); },
      toggleFullscreen: toggleFullscreen, row: row, unplayable: unplayable,
      setMarks: function (times) { marks = times.slice(); placeMarks(); },
      on: function (name, fn) { video.addEventListener(name, fn); }
    };
    box.__player = api;
    players.push(api);
    if (!active) active = api;
    attach();
    placeTicks();
    paint();
    paintMuted();
    return api;
  }

  /* Jumping from a list below the video (phones): bring the video back into view. */
  function jumpTo(player, t) {
    player.seek(t);
    player.play();
    var r = player.element.getBoundingClientRect();
    if (r.bottom < 80 || r.top > window.innerHeight - 80) player.element.scrollIntoView({ block: 'start', behavior: reduceMotion ? 'auto' : 'smooth' });
  }

  /* Chapters and transcript lines: click to jump, current one marked. */
  function bindList(list, player, follow) {
    var items = Array.prototype.slice.call(list.querySelectorAll('[data-start]'));
    if (!items.length) return;
    // The list follows playback inside whatever scrolls it: its own lines,
    // or the side column on wide screens. The page itself never jumps.
    function scrollerOf() {
      var own = list.querySelector('.transcript-lines');
      if (own && own.scrollHeight > own.clientHeight) return own;
      var side = list.closest('.page-side');
      return side && side.scrollHeight > side.clientHeight ? side : null;
    }
    var userScrolled = 0, current = null;
    var area = list.closest('.page-side') || list;
    area.addEventListener('wheel', function () { userScrolled = Date.now(); }, { passive: true });
    area.addEventListener('touchmove', function () { userScrolled = Date.now(); }, { passive: true });
    items.forEach(function (item) {
      item.addEventListener('click', function () { jumpTo(player, parseFloat(item.getAttribute('data-start'))); });
    });
    function mark() {
      var t = player.video.currentTime, next = null;
      for (var i = items.length - 1; i >= 0; i--) {
        if (parseFloat(items[i].getAttribute('data-start')) <= t + 0.05) { next = items[i]; break; }
      }
      if (next === current) return;
      if (current) { current.classList.remove('is-current'); current.removeAttribute('aria-current'); }
      current = next;
      if (!current) return;
      current.classList.add('is-current');
      current.setAttribute('aria-current', 'true');
      var box = follow && Date.now() - userScrolled > 4000 ? scrollerOf() : null;
      if (box) {
        var top = box.scrollTop + current.getBoundingClientRect().top - box.getBoundingClientRect().top - box.clientHeight / 3;
        box.scrollTo({ top: Math.max(0, top), behavior: reduceMotion ? 'auto' : 'smooth' });
      }
    }
    player.on('timeupdate', mark);
    player.on('seeked', mark);
  }

  /* Comments through a host's interface: window.bingsuComments = { load(), post(c) }. */
  function bindComments(section, player) {
    var api = window.bingsuComments;
    if (!api || typeof api.load !== 'function') return;
    section.hidden = false;
    var empty = make('p', 'comments-empty', section);
    empty.textContent = 'No comments yet.';
    empty.hidden = true;
    var list = make('ol', 'comments-list', section);
    var form = make('form', 'comment-form', section);
    var name = make('input', 'comment-name', form);
    name.type = 'text';
    name.name = 'author';
    name.autocomplete = 'name';
    name.placeholder = 'Your name';
    name.setAttribute('aria-label', 'Your name');
    name.maxLength = 80;
    try { name.value = localStorage.getItem('share-comment-name') || ''; } catch (e) {}
    var text = make('textarea', 'comment-text', form);
    text.placeholder = 'Add a comment';
    text.name = 'text';
    text.setAttribute('aria-label', 'Comment');
    text.maxLength = 2000;
    text.required = true;
    text.rows = 1;
    // Grows with what is typed (where CSS field-sizing is not there yet).
    text.addEventListener('input', function () { text.style.height = 'auto'; text.style.height = text.scrollHeight + 'px'; });
    var foot = make('div', 'comment-form-row', form);
    var atLabel = make('label', 'comment-at-choice', foot);
    var at = make('input', '', atLabel);
    at.type = 'checkbox';
    at.name = 'at';
    at.checked = true;
    var atText = make('span', '', atLabel);
    var status = make('span', 'comment-status', foot);
    status.setAttribute('role', 'status');
    var send = make('button', 'button comment-post', foot);
    send.type = 'submit';
    send.textContent = 'Post';
    function stamp() { atText.textContent = 'At ' + clock(player ? player.video.currentTime : 0); }
    stamp();
    if (player) player.on('timeupdate', stamp);
    function render(items) {
      list.textContent = '';
      empty.hidden = !!(items && items.length);
      (items || []).forEach(function (c) {
        var li = make('li', 'comment', list);
        var head = make('div', 'comment-head', li);
        make('strong', 'comment-author', head).textContent = c.author || 'Someone';
        if (typeof c.at === 'number' && player) {
          var jump = make('button', 'comment-at', head);
          jump.type = 'button';
          jump.textContent = clock(c.at);
          jump.addEventListener('click', function () { player.seek(c.at); player.play(); });
        }
        if (c.createdAt) {
          var when = make('time', 'comment-date', head);
          var date = new Date(c.createdAt);
          if (!isNaN(date)) { when.dateTime = date.toISOString(); when.textContent = new Intl.DateTimeFormat(root.lang || undefined, { dateStyle: 'medium' }).format(date); }
        }
        make('p', 'comment-body', li).textContent = c.text || '';
      });
    }
    function reload() { return Promise.resolve(api.load()).then(render).catch(function () { status.textContent = 'Comments could not be loaded.'; }); }
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!text.value.trim()) return;
      var comment = { author: name.value.trim(), text: text.value.trim() };
      if (at.checked && player) comment.at = Math.round(player.video.currentTime * 10) / 10;
      try { localStorage.setItem('share-comment-name', comment.author); } catch (err) {}
      send.disabled = true;
      status.textContent = 'Posting…';
      Promise.resolve(api.post(comment)).then(function () {
        text.value = '';
        text.style.height = '';
        status.textContent = '';
        return reload();
      }).catch(function () { status.textContent = 'Your comment could not be posted. Try again.'; })
        .then(function () { send.disabled = false; });
    });
    reload();
  }


  /* The viewer's own notes: kept in this browser only (localStorage, keyed
     by the page's path), exported by copying or downloading, and sent only
     when the page names an endpoint and the viewer presses Send. Stored
     notes are read as untrusted: another page on the same host can write
     the same storage, so they are checked and shown as text. */
  var startNote = null;
  function bindNotes(section, player) {
    var KEY = 'share-notes:' + location.pathname.replace(/index\.html$/, '');
    var MAX_TEXT = 2000, MAX_NOTES = 500;
    var endpoint = section.getAttribute('data-notes-endpoint');
    var notes = load(), pendingAt = null, resume = false, removed = null, undoTimer = 0;
    section.hidden = false;

    function load() {
      var raw;
      try { raw = JSON.parse(localStorage.getItem(KEY) || '[]'); } catch (e) { raw = []; }
      if (!Array.isArray(raw)) return [];
      return raw.filter(function (n) {
        return n && typeof n.at === 'number' && isFinite(n.at) && n.at >= 0 && typeof n.text === 'string' && n.text.trim();
      }).slice(0, MAX_NOTES).map(function (n) {
        return { id: String(n.id || Math.random().toString(36).slice(2)).slice(0, 40), at: n.at, text: n.text.slice(0, MAX_TEXT),
                 createdAt: typeof n.createdAt === 'string' ? n.createdAt.slice(0, 40) : '' };
      });
    }
    function save() {
      try { localStorage.setItem(KEY, JSON.stringify(notes)); return true; } catch (e) { say('Notes could not be saved in this browser.'); return false; }
    }

    var hint = make('p', 'notes-hint', section);
    hint.textContent = 'Private to this browser until you copy or send them.';
    var form = make('form', 'notes-form', section);
    var formRow = make('div', 'notes-form-row', form);
    var text = make('textarea', 'notes-text', formRow);
    text.name = 'note';
    text.rows = 1;
    text.maxLength = MAX_TEXT;
    text.autocomplete = 'off';
    var add = make('button', 'notes-button notes-add', formRow);
    add.type = 'submit';
    add.textContent = 'Add Note';
    var keys = make('p', 'notes-keys', form);
    keys.setAttribute('aria-hidden', 'true');
    keys.textContent = 'Enter adds · Esc cancels';
    var empty = make('p', 'notes-empty', section);
    empty.innerHTML = '<span class="notes-empty-keys">Press <kbd>N</kbd> or the note button on the video to mark a moment.</span><span class="notes-empty-touch">Add a note above to mark this moment.</span>';
    var list = make('ol', 'notes-list', section);
    var undoRow = make('div', 'notes-undo-row', section);
    undoRow.hidden = true;
    make('span', '', undoRow).textContent = 'Note deleted.';
    var undoBtn = make('button', 'notes-undo', undoRow);
    undoBtn.type = 'button';
    undoBtn.textContent = 'Undo';
    var tools = make('div', 'notes-tools', section);
    /* Screen readers hear what happened; the pressed control shows it. */
    var status = make('p', 'notes-status', section);
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');

    function now() { return Math.round((player.video.currentTime || 0) * 10) / 10; }
    function label() {
      var at = clock(pendingAt === null ? now() : pendingAt);
      text.placeholder = 'Add a note at ' + at + '…';
      text.setAttribute('aria-label', 'Note at ' + at);
    }
    function say(message) { status.textContent = message; }
    /* "Copied" on the control itself for 2 s, then its own label again. */
    function flash(control, label) {
      if (!control.dataset.label) control.dataset.label = control.textContent;
      control.textContent = label;
      clearTimeout(control.flashTimer);
      control.flashTimer = setTimeout(function () { control.textContent = control.dataset.label; }, 2000);
    }

    /* N, the note button or focusing the field: hold the moment and pause. */
    function begin() {
      if (pendingAt === null) {
        pendingAt = now();
        resume = !player.video.paused && !player.video.ended;
        player.pause();
        label();
      }
    }
    startNote = function () { begin(); text.focus(); };
    function finish(keepPlaying) {
      pendingAt = null;
      label();
      if (keepPlaying && resume) player.play();
      resume = false;
    }
    text.addEventListener('focus', begin);
    text.addEventListener('input', function () { text.style.height = 'auto'; text.style.height = text.scrollHeight + 'px'; });
    text.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); form.requestSubmit ? form.requestSubmit() : submit(e); }
      else if (e.key === 'Escape') { e.preventDefault(); text.blur(); }
    });
    text.addEventListener('blur', function () { if (!text.value.trim()) finish(true); });
    form.addEventListener('submit', submit);
    function submit(e) {
      if (e) e.preventDefault();
      var value = text.value.trim();
      if (!value) return;
      if (notes.length >= MAX_NOTES) return say('This page holds ' + MAX_NOTES + ' notes. Delete some to add more.');
      var at = pendingAt === null ? now() : pendingAt;
      notes.push({ id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), at: at, text: value.slice(0, MAX_TEXT), createdAt: new Date().toISOString() });
      if (!save()) { notes.pop(); return; }
      text.value = '';
      text.style.height = '';
      render();
      say('Note added at ' + clock(at) + '.');
      var playing = resume;
      text.blur();
      finish(playing);
    }

    function remove(note) {
      var index = notes.indexOf(note);
      if (index < 0) return;
      notes.splice(index, 1);
      save();
      render();
      clearTimeout(undoTimer);
      removed = { note: note, index: index };
      undoRow.hidden = false;
      say('Note deleted.');
      undoTimer = setTimeout(function () { removed = null; undoRow.hidden = true; }, 8000);
    }
    undoBtn.addEventListener('click', function () {
      if (!removed) return;
      notes.splice(Math.min(removed.index, notes.length), 0, removed.note);
      removed = null;
      undoRow.hidden = true;
      save();
      render();
      say('Note restored.');
    });

    function sorted() { return notes.slice().sort(function (a, b) { return a.at - b.at; }); }
    function render() {
      list.textContent = '';
      var items = sorted();
      items.forEach(function (n) {
        var li = make('li', 'note', list);
        var jump = make('button', 'note-at', li);
        jump.type = 'button';
        jump.textContent = clock(n.at);
        jump.setAttribute('aria-label', 'Play from ' + clock(n.at));
        jump.addEventListener('click', function () { jumpTo(player, n.at); });
        make('p', 'note-text', li).textContent = n.text;
        var del = make('button', 'note-delete', li);
        del.type = 'button';
        del.setAttribute('aria-label', 'Delete note at ' + clock(n.at));
        del.title = 'Delete';
        del.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 7l10 10M17 7L7 17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
        del.addEventListener('click', function () { remove(n); });
      });
      empty.hidden = items.length > 0;
      tools.hidden = items.length === 0;
      if (player.setMarks) player.setMarks(items.map(function (n) { return n.at; }));
    }

    /* Exports. The page's published address when it has one, never a local one. */
    function pageURL() {
      var canonical = document.querySelector('link[rel="canonical"]');
      if (canonical && canonical.href) return canonical.href;
      return /^https?:$/.test(location.protocol) && !/^(127\.0\.0\.1|localhost|\[::1\])$/.test(location.hostname) ? location.href.replace(/#.*$/, '') : '';
    }
    function title() { var h = document.querySelector('.title'); return (h ? h.textContent : document.title).trim(); }
    function moment(at) { var url = pageURL(); return url ? url + '#t=' + Math.floor(at) : ''; }
    function markdown() {
      var url = pageURL();
      var lines = ['# Notes on ' + title(), ''];
      if (url) lines.push(url, '');
      sorted().forEach(function (n) {
        var at = moment(n.at) ? '[' + clock(n.at) + '](' + moment(n.at) + ')' : clock(n.at);
        lines.push('- ' + at + ' ' + n.text.replace(/\n/g, '\n  '));
      });
      return lines.join('\n') + '\n';
    }
    function emailReply() {
      var url = pageURL();
      var lines = ['My notes on "' + title() + '"' + (url ? ' (' + url + ')' : '') + ':', ''];
      sorted().forEach(function (n) { lines.push(clock(n.at) + '  ' + n.text.replace(/\n/g, '\n      ')); });
      return lines.join('\n') + '\n';
    }
    function payload() {
      return JSON.stringify({ page: { title: title(), url: pageURL() || null }, notes: sorted().map(function (n) {
        return { at: n.at, text: n.text, createdAt: n.createdAt || null };
      }), exportedAt: new Date().toISOString() }, null, 2);
    }
    function copy(value, done, control) {
      function shown(ok) { say(ok ? done : 'Copying is blocked here. Download them instead.'); flash(control, ok ? 'Copied' : 'Not copied'); }
      function fallback() {
        var area = make('textarea', 'notes-copy', document.body);
        area.value = value;
        area.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) {}
        area.remove();
        shown(ok);
      }
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(value).then(function () { shown(true); }, fallback);
      else fallback();
    }

    /* Export: one menu button. Arrow keys move, Escape closes. */
    var menuWrap = make('div', 'notes-menu-wrap', tools);
    var exportBtn = make('button', 'notes-button notes-export', menuWrap);
    exportBtn.type = 'button';
    exportBtn.textContent = 'Export';
    exportBtn.setAttribute('aria-haspopup', 'menu');
    exportBtn.setAttribute('aria-expanded', 'false');
    var menu = make('div', 'notes-menu', menuWrap);
    menu.setAttribute('role', 'menu');
    menu.id = 'notes-export-menu';
    exportBtn.setAttribute('aria-controls', menu.id);
    menu.hidden = true;
    function item(label, fn) {
      var b = make('button', 'notes-menu-item', menu);
      b.type = 'button';
      b.setAttribute('role', 'menuitem');
      b.tabIndex = -1;
      b.textContent = label;
      b.addEventListener('click', function () { closeMenu(true); fn(); });
      return b;
    }
    function items() { return Array.prototype.slice.call(menu.querySelectorAll('[role="menuitem"]')); }
    function openMenu() { menu.hidden = false; exportBtn.setAttribute('aria-expanded', 'true'); items()[0].focus(); }
    function closeMenu(refocus) { if (menu.hidden) return; menu.hidden = true; exportBtn.setAttribute('aria-expanded', 'false'); if (refocus) exportBtn.focus(); }
    exportBtn.addEventListener('click', function () { if (menu.hidden) openMenu(); else closeMenu(false); });
    menu.addEventListener('keydown', function (e) {
      var list = items(), i = list.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') list[(i + 1) % list.length].focus();
      else if (e.key === 'ArrowUp') list[(i - 1 + list.length) % list.length].focus();
      else if (e.key === 'Home') list[0].focus();
      else if (e.key === 'End') list[list.length - 1].focus();
      else if (e.key === 'Escape' || e.key === 'Tab') { closeMenu(e.key === 'Escape'); if (e.key === 'Tab') return; }
      else return;
      e.preventDefault();
      e.stopPropagation();
    });
    document.addEventListener('pointerdown', function (e) { if (!menuWrap.contains(e.target)) closeMenu(false); });
    item('Copy as Markdown', function () { copy(markdown(), 'Copied as Markdown.', exportBtn); });
    item('Copy as Email Reply', function () { copy(emailReply(), 'Copied. Paste it into your reply.', exportBtn); });
    item('Download JSON', function () {
      var a = make('a', '', document.body);
      a.href = URL.createObjectURL(new Blob([payload()], { type: 'application/json' }));
      a.download = 'notes.json';
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      say('Downloaded notes.json.');
      flash(exportBtn, 'Downloaded');
    });
    // Encrypted shares send nothing (sealed replies come later); Export stays.
    if (endpoint && !sealed) {
      var host = '';
      try { host = new URL(endpoint).host; } catch (e) {}
      var send = make('button', 'notes-button notes-send', tools);
      send.type = 'button';
      send.textContent = 'Send';
      send.title = 'Sends your notes to ' + host + ', set up by the page\'s owner';
      send.setAttribute('aria-label', 'Send notes to ' + host);
      send.addEventListener('click', function () {
        send.disabled = true;
        send.textContent = 'Sending…';
        fetch(endpoint, { method: 'POST', mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store',
                          headers: { 'Content-Type': 'application/json' }, body: payload() })
          .then(function (r) { if (!r.ok) throw new Error(String(r.status)); say('Sent to ' + host + '.'); flash(send, 'Sent'); })
          .catch(function () { say('Could not send to ' + host + '. Try again, or copy them instead.'); flash(send, 'Not sent'); })
          .then(function () { send.disabled = false; });
      });
      send.dataset.label = 'Send';
    }

    /* A note button by the time in the player. */
    var noteBtn = null;
    if (player.row) {
      noteBtn = button('player-note', 'Add a note (N)', '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 5.5A1.5 1.5 0 0 1 6.5 4h11A1.5 1.5 0 0 1 19 5.5v9a1.5 1.5 0 0 1-1.5 1.5H10l-4 3.5V16h0.5A1.5 1.5 0 0 1 5 14.5z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 7.5v5M9.5 10h5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>');
      var spacer = player.row.querySelector('.player-spacer');
      player.row.insertBefore(noteBtn, spacer ? spacer.nextSibling : null);
      noteBtn.addEventListener('click', function () {
        startNote();
        if (section.getBoundingClientRect().top > window.innerHeight || section.getBoundingClientRect().bottom < 0) {
          section.scrollIntoView({ block: 'nearest', behavior: reduceMotion ? 'auto' : 'smooth' });
        }
      });
    }
    player.on('timeupdate', function () { if (pendingAt === null) label(); });
    label();
    render();
    /* A video that cannot play here has no moment to note. */
    function disable() {
      text.disabled = add.disabled = true;
      section.hidden = true;
      if (noteBtn) noteBtn.remove();
      startNote = null;
    }
    if (player.unplayable && player.unplayable()) disable(); else player.element.addEventListener('unplayable', disable);
  }

  /* A search field over the transcript: filters lines as you type; Enter plays the first. */
  function bindSearch(section, player) {
    var lines = Array.prototype.slice.call(section.querySelectorAll('[data-start]'));
    if (lines.length < 2) return;
    var field = make('input', 'transcript-search');
    field.type = 'search';
    field.name = 'transcript-search';
    field.autocomplete = 'off';
    field.spellcheck = false;
    field.placeholder = 'Search the transcript…';
    field.setAttribute('aria-label', 'Search the transcript');
    var heading = section.querySelector('h2');
    section.insertBefore(field, heading ? heading.nextSibling : section.firstChild);
    var none = make('p', 'transcript-none');
    none.hidden = true;
    none.setAttribute('role', 'status');
    field.parentNode.insertBefore(none, field.nextSibling);
    field.addEventListener('input', function () {
      var q = field.value.trim().toLowerCase(), shown = 0;
      lines.forEach(function (l) { var hit = !q || l.textContent.toLowerCase().indexOf(q) >= 0; l.hidden = !hit; if (hit) shown++; });
      none.hidden = shown > 0;
      none.textContent = shown ? '' : 'No line has “' + field.value.trim() + '”.';
    });
    field.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter') return;
      var first = lines.filter(function (l) { return !l.hidden; })[0];
      if (first) { e.preventDefault(); jumpTo(player, parseFloat(first.getAttribute('data-start'))); }
    });
  }

  /* #t=83 opens the page at that second (links in exported notes use it). */
  function startAtHash(player) {
    var m = /(?:^#|&)t=(\d+(?:\.\d+)?)/.exec(location.hash);
    if (!m) return;
    var t = parseFloat(m[1]);
    player.seek(t);
    var once = function () { player.video.removeEventListener('loadedmetadata', once); player.seek(t); };
    player.video.addEventListener('loadedmetadata', once);
  }

  function currentTheme() {
    var t = root.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  function paintThemeChoice() {
    var choice = savedTheme();
    if (choice !== 'light' && choice !== 'dark') choice = 'system';
    Array.prototype.forEach.call(document.querySelectorAll('[data-theme-choice]'), function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-theme-choice') === choice));
    });
    var frame = document.querySelector('iframe.giscus-frame');
    if (frame) frame.contentWindow.postMessage({ giscus: { setConfig: { theme: currentTheme() } } }, 'https://giscus.app');
  }
  function chooseTheme(choice) {
    try { if (choice === 'system') localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, choice); } catch (e) {}
    applyTheme(choice);
    paintThemeChoice();
  }

  function start() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-player]'), function (box) { mount(box); });
    var first = players[0];
    Array.prototype.forEach.call(document.querySelectorAll('[data-theme-choice]'), function (b) {
      b.addEventListener('click', function () { chooseTheme(b.getAttribute('data-theme-choice')); });
    });
    paintThemeChoice();
    if (window.matchMedia) matchMedia('(prefers-color-scheme: light)').addEventListener('change', paintThemeChoice);
    var giscus = document.querySelector('[data-giscus] script');
    if (giscus) giscus.setAttribute('data-theme', currentTheme());
    if (!first) return;
    Array.prototype.forEach.call(document.querySelectorAll('[data-chapters]'), function (l) { bindList(l, first, false); });
    Array.prototype.forEach.call(document.querySelectorAll('[data-transcript]'), function (l) { bindList(l, first, true); });
    Array.prototype.forEach.call(document.querySelectorAll('[data-transcript]'), function (l) { bindSearch(l, first); });
    Array.prototype.forEach.call(document.querySelectorAll('[data-comments]'), function (s) { bindComments(s, first); });
    var notesSection = document.querySelector('[data-notes]');
    if (notesSection) bindNotes(notesSection, first);
    startAtHash(first);
  }

  document.addEventListener('keydown', function (e) {
    var p = active;
    if (!p || e.metaKey || e.ctrlKey || e.altKey || typing(e.target)) return;
    var onControl = e.target && (e.target.tagName === 'BUTTON' || e.target.tagName === 'A');
    var key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
    switch (key) {
      case ' ': case 'k': if (key === ' ' && onControl) return; p.toggle(); break;
      case 'ArrowLeft': p.seek(p.video.currentTime - 5); break;
      case 'ArrowRight': p.seek(p.video.currentTime + 5); break;
      case 'j': p.seek(p.video.currentTime - 10); break;
      case 'l': p.seek(p.video.currentTime + 10); break;
      case 'n': if (!startNote) return; startNote(); break;
      case 'f': p.toggleFullscreen(); break;
      case 'c': p.toggleCaptions(); break;
      case 'm': p.video.muted = !p.video.muted; break;
      default: return;
    }
    e.preventDefault();
  });

  /* An encrypted share (design section 3). The shell names nothing; the key
     after #k= leaves the address at once and opens the sealed files here, in
     memory. Their bytes never reach the page except through openFile. */
  var sealed = null;
  var TYPES = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', vtt: 'text/vtt',
                css: 'text/css', mp4: 'video/mp4', m4a: 'audio/mp4', json: 'application/json', md: 'text/markdown', txt: 'text/plain' };
  /* P.bse's bytes, or null when the host has no such file. */
  function fetchSealed(path) {
    if (!e2e.isSharePath(path)) return Promise.reject(new Error('not a share path'));
    if (INLINE) return Promise.resolve(Object.prototype.hasOwnProperty.call(INLINE.files, path) ? inlineBytes(INLINE.files[path]) : null);
    return fetch(folder + path + '.bse', { credentials: 'same-origin', referrerPolicy: 'no-referrer' }).then(function (r) {
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(String(r.status));
      return r.arrayBuffer().then(function (b) { return new Uint8Array(b); });
    });
  }
  /* `file` opens and checks one file (e2e.reader); this adds blob: addresses. */
  function sealedFiles(file) {
    return {
      file: file,
      url: function (path) {
        return file(path).then(function (b) { return URL.createObjectURL(new Blob([b], { type: TYPES[path.split('.').pop().toLowerCase()] || 'application/octet-stream' })); });
      }
    };
  }

  /* hls.js asks this loader for playlists and segments; each comes from P.bse, decrypted. */
  function SealedLoader() {
    this.context = null;
    this.aborted = false;
    this.stats = { aborted: false, loaded: 0, retry: 0, total: 0, chunkCount: 0, bwEstimate: 0,
                   loading: { start: 0, first: 0, end: 0 }, parsing: { start: 0, end: 0 }, buffering: { start: 0, first: 0, end: 0 } };
  }
  SealedLoader.prototype.load = function (context, config, callbacks) {
    // The first playlist comes as written in the page, the rest already resolved.
    var self = this, stats = this.stats, url = new URL(context.url, location.href).href.split(/[?#]/)[0];
    var path = url.indexOf(folder) === 0 ? url.slice(folder.length) : '';
    this.context = context;
    stats.loading.start = performance.now();
    sealed.file(path).then(function (plain) {
      if (self.aborted) return;
      var data = context.rangeEnd ? plain.slice(context.rangeStart || 0, context.rangeEnd) : plain;
      stats.loading.first = stats.loading.end = performance.now();
      stats.loaded = stats.total = data.byteLength;
      callbacks.onSuccess({ url: context.url, code: 200, data: context.responseType === 'arraybuffer' ? data.buffer : e2e.text(data) }, stats, context, null);
    }, function () {
      // Refused, not retried: a piece that does not decrypt will not the next time either.
      if (!self.aborted) callbacks.onError({ code: 403, text: 'did not decrypt' }, context, null, stats);
    });
  };
  SealedLoader.prototype.abort = function () { this.aborted = this.stats.aborted = true; };
  SealedLoader.prototype.destroy = function () { this.abort(); this.context = null; };

  /* content.html is the sender's, so it is rebuilt from an allowlist of what
     the built-in templates write: no scripts, styles, frames, forms or
     handlers; href only https:, mailto: or a file of the share; src only a
     file of the share, decrypted later. */
  var TAGS = ('a aside b br button code div em footer h1 h2 h3 header i img kbd li main nav ol p section span strong time ul video '
    + 'svg path rect circle line polyline g').split(' ');
  var ATTRS = /^(class|id|hidden|role|title|lang|dir|alt|datetime|download|rel|width|height|playsinline|preload|type|href|src|viewbox|d|fill|stroke|stroke-width|stroke-linecap|stroke-linejoin|x|y|rx|ry|cx|cy|r|x1|y1|x2|y2|points|aria-[a-z-]+|data-[a-z0-9-]+)$/;
  var PATH_DATA = /^data-(playlist|mp4|poster|captions)$/;
  function safeHref(v) {
    return /^https:\/\/[^\s\u0000-\u001f\\]+$/i.test(v) || /^mailto:[^\s\u0000-\u001f]+$/i.test(v) || /^#[A-Za-z0-9_=&.-]*$/.test(v) || e2e.isSharePath(v);
  }
  function sanitize(html) {
    var out = document.createDocumentFragment();
    (function copy(from, to) {
      Array.prototype.forEach.call(from.childNodes, function (n) {
        if (n.nodeType === 3) return to.appendChild(document.createTextNode(n.data));
        var svg = n instanceof SVGElement;
        if (n.nodeType !== 1 || TAGS.indexOf(n.localName) < 0 || (svg !== (['svg', 'path', 'rect', 'circle', 'line', 'polyline', 'g'].indexOf(n.localName) >= 0))) return;
        var el = svg ? document.createElementNS(n.namespaceURI, n.localName) : document.createElement(n.localName);
        Array.prototype.forEach.call(n.attributes, function (a) {
          var name = a.name.toLowerCase(), v = a.value;
          if (!ATTRS.test(name) || name === 'data-notes-endpoint') return;
          if ((name === 'href' && !safeHref(v)) || (name === 'type' && v !== 'button') || (name === 'id' && !e2e.safeId(v))) return;
          if (PATH_DATA.test(name) && !e2e.isSharePath(v)) return;
          if (name === 'src') { if (n.localName === 'img' && e2e.isSharePath(v)) el.setAttribute('data-sealed-src', v); return; }
          el.setAttribute(a.name, v);
        });
        to.appendChild(el);
        copy(n, el);
      });
    })(new DOMParser().parseFromString(html, 'text/html').body, out);
    return out;
  }

  /* Links to the share's own files (the download, agent.md) save the decrypted file. */
  function saveSealed(e) {
    var a = e.target.closest && e.target.closest('a[href]'), path = a && a.getAttribute('href');
    if (e.defaultPrevented || !path || !e2e.isSharePath(path)) return;
    e.preventDefault();
    if (a.getAttribute('aria-busy') === 'true') return;
    a.setAttribute('aria-busy', 'true');
    sealed.url(path).then(function (u) {
      var t = make('a', '', document.body);
      t.href = u;
      t.download = a.getAttribute('download') || path.split('/').pop();
      t.click();
      t.remove();
      setTimeout(function () { URL.revokeObjectURL(u); }, 60000);
    }).catch(function () {}).then(function () { a.removeAttribute('aria-busy'); });
  }

  /* Who signed it and whether the signature held, under the title. */
  function provenance(o, plain) {
    var meta = document.querySelector('.summary .meta');
    if (!meta) return;
    var line = make('p', 'share-provenance'), p = e2e.provenance(o.signature, plain);
    line.textContent = p.text;
    if (p.fingerprint) {
      line.appendChild(document.createTextNode(' · code '));
      make('span', 'share-key', line).textContent = p.fingerprint;
      line.appendChild(document.createTextNode(', which should match the one the sender gives you'));
    }
    meta.parentNode.insertBefore(line, meta.nextSibling);
  }

  /* In the page's own frame: the title is sealed, so a neutral one stands in. */
  function lockScreen() {
    var main = make('main', 'page share-lock', document.body), box = make('div', 'share-lock-box', main);
    make('h1', 'title share-lock-heading', box).textContent = 'Shared video';
    var title = make('h2', 'share-lock-title', box), note = make('p', 'share-lock-text', box);
    title.id = 'share-lock-title';
    main.setAttribute('aria-labelledby', title.id);
    main.hidden = true;
    return {
      main: main, box: box,
      say: function (t, n) { title.textContent = t; note.textContent = n || ''; note.hidden = !n; main.hidden = false; }
    };
  }
  function explain(e) {
    var code = e && e.code;
    if (code === 'locked') return ['This link does not open this share.', 'Check that you have the whole link, including the part after #.'];
    if (code === 'expired') {
      return ['This share has expired.', 'It expired on ' + new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(e.detail) + '. Ask the sender for a new one.'];
    }
    if (code === 'signature') return ['The signature does not match the sender this link names.', 'It is not shown. Ask the sender for the link again.'];
    return ['This share could not be opened.', 'A file in it is damaged or missing. Ask the sender for the link again.'];
  }
  function askPasscode(lock, attempt) {
    lock.say('Enter passcode', 'The link and this passcode together unlock the video, here in your browser. '
      + 'The passcode is not in the link and is not sent anywhere. Ask the sender for it.');
    var form = make('form', 'share-lock-form', lock.box);
    form.noValidate = true;
    var field = make('input', 'share-lock-input', form);
    field.id = 'share-passcode';
    field.name = 'passcode';
    field.type = 'text';
    field.autocomplete = 'off';
    field.spellcheck = false;
    field.setAttribute('aria-labelledby', 'share-lock-title');
    field.setAttribute('autocapitalize', 'characters');
    field.setAttribute('autocorrect', 'off');
    field.setAttribute('enterkeyhint', 'go');
    field.setAttribute('aria-describedby', 'share-passcode-error');
    var error = make('p', 'share-lock-error', form);
    error.id = 'share-passcode-error';
    error.setAttribute('aria-live', 'polite');
    var go = make('button', 'share-lock-open', form);
    go.type = 'submit';
    go.textContent = 'Open';
    field.focus();
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (go.disabled) return;
      if (!e2e.normalizePasscode(field.value)) return field.focus();
      go.disabled = field.readOnly = true;
      go.textContent = 'Opening…';
      error.textContent = '';
      field.removeAttribute('aria-invalid');
      attempt(field.value).then(function (r) { reveal(r, lock); }, function (err) {
        go.disabled = field.readOnly = false;
        go.textContent = 'Open';
        if (err && err.code !== 'locked') { form.remove(); return lock.say.apply(null, explain(err)); }
        error.textContent = 'Wrong passcode, or this link is for another share. Check both with the sender.';
        field.setAttribute('aria-invalid', 'true');
        field.value = '';
        field.focus();
      });
    });
  }
  function reveal(r, lock) {
    var o = r.opened, page = o.page;
    sealed = sealedFiles(o.file);
    lock.main.remove();
    document.title = page.title;
    if (/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$/.test(page.language || '')) root.lang = page.language;
    document.body.appendChild(sanitize(o.html));
    provenance(o);
    Array.prototype.forEach.call(document.querySelectorAll('img[data-sealed-src]'), function (img) {
      sealed.url(img.getAttribute('data-sealed-src')).then(function (u) { img.src = u; }, function () {});
    });
    if (page.brand) sealed.url('brand.css').then(function (u) { var l = make('link', '', document.head); l.rel = 'stylesheet'; l.href = u; }, function () {});
    document.addEventListener('click', saveSealed);
    start();
  }
  function openSealed() {
    document.title = 'Shared video';
    var hash = INLINE ? INLINE.link : location.hash.replace(/^#/, ''), link = e2e.linkKey(hash), pin = e2e.signerPin(hash);
    var rest = hash.split('&').filter(function (p) { return p && p.indexOf('k=') !== 0; }).join('&');
    if (!INLINE && rest !== hash) history.replaceState(history.state, '', location.pathname + location.search + (rest ? '#' + rest : ''));
    var lock = lockScreen();
    var stubbed = INLINE ? Promise.resolve(INLINE.stub)
      : fetch(folder + 'agent.json', { credentials: 'same-origin' }).then(function (res) { return res.json(); });
    stubbed.then(e2e.readStub).then(function (stub) {
      if (!e2e.supported) return lock.say('This share opens only over a secure connection.', 'Open its https:// address.');
      if (!link) {
        return stub.recipientBound ? lock.say('This share opens only for the people it was made for.', 'They open it in their own app.')
          : lock.say('This link is missing its key.', 'Ask the sender for the whole link, including the part after #.');
      }
      function once(passcode) {
        return e2e.keys(stub, link, passcode).then(function (k) {
          return e2e.open(fetchSealed, k, new Date(), pin, INLINE ? null : fetchClear).then(function (opened) { return { keys: k, opened: opened }; });
        });
      }
      // The stub's flags are the host's: the link and the sealed files decide. A passcode that
      // does not open it is tried once without, in case the share has none.
      function attempt(passcode) {
        return once(passcode).catch(function (e) { if (passcode == null || e.code !== 'locked') throw e; return once(null).catch(function () { throw e; }); });
      }
      return attempt(null).then(function (r) { reveal(r, lock); }, function (e) {
        if (e.code !== 'locked') return lock.say.apply(null, explain(e));
        if (stub.gate) return lock.say('This share needs its relay, which is not set up yet.');
        return askPasscode(lock, attempt);
      });
    }, function () { lock.say('This share could not be opened.', 'Its files are not all at this address.'); });
  }

  /* A plain page's file, or null when the host has none. */
  function fetchClear(path) {
    return fetch(folder + path, { credentials: 'same-origin', referrerPolicy: 'no-referrer' }).then(function (r) {
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(String(r.status));
      return r.arrayBuffer().then(function (b) { return new Uint8Array(b); });
    });
  }
  /* A plain page whose link names its signer plays only once the signature holds. */
  function openSigned(pin) {
    var page = Array.prototype.slice.call(document.body.children);
    page.forEach(function (el) { el.hidden = true; });
    var check = e2e.supported ? e2e.checkPlain(fetchClear, pin) : Promise.resolve({ state: 'unchecked' });
    check.then(function (s) {
      page.forEach(function (el) { el.hidden = false; });
      start();
      provenance({ signature: s }, true);
    }, function (e) { lockScreen().say.apply(null, explain(e && e.code === 'signature' ? e : { code: 'signature' })); });
  }

  // The link decides the mode, not the host's markup: a `k=` means sealed, whatever the shell says.
  function boot() {
    if (e2e.linkKey(location.hash) || document.body.hasAttribute('data-encrypted-share')) return openSealed();
    var pin = e2e.signerPin(location.hash);
    if (pin) openSigned(pin); else start();
  }
  window.BingsuPlayer = { mount: mount, players: players, version: 1 };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();