// "Check something" box on keys.bensoyka.com.
//
// Everything runs in the browser against keys.json (generated from the same data
// as the signed keys.txt) and the published key files. Nothing is sent anywhere.
//
// Key decisions:
// - OpenPGP.js is vendored (pinned version, served from this site), not loaded
//   from a CDN, so a third party can't change what this page runs.
// - Certificates are matched by exact SHA-256 of their bytes: a certificate is
//   mine if and only if it's byte-for-byte one I've published.
// - Results are built with textContent only; pasted input is never put into the
//   page as HTML.

import * as openpgp from "/vendor/openpgp-6.3.2.min.mjs";

const $ = (id) => document.getElementById(id);
const data = await (await fetch("/keys.json")).json();

// Revocation banner. /status.json only exists after the PGP watch (bsoyka/sirloin)
// has seen a valid revocation of my main key; it's never part of a deploy, so a
// stale deploy can't hide it. Missing or unreadable means "nothing to report".
let revoked = null;
try {
  const r = await fetch("/status.json", { cache: "no-store" });
  if (r.ok) revoked = (await r.json()).main_key_revoked || null;
} catch { /* no status file */ }
if (revoked) {
  const el = $("alert");
  const box = document.createElement("div");
  const head = document.createElement("strong");
  head.textContent = "Don't trust anything on this page right now.";
  const p1 = document.createElement("p");
  p1.textContent = `My main PGP key was revoked on ${revoked}, and this page hasn't been ` +
    "updated since. Fingerprints, certificates, and downloads below may be out " +
    "of date, and anything signed with that key can no longer be relied on.";
  const p2 = document.createElement("p");
  p2.textContent = "If you need to verify something from me, reach me through a channel you already trust.";
  box.append(head, p1, p2);
  el.append(box);
  el.hidden = false;
  $("check").remove(); // no checker while the page can't vouch for anything
}

let keysPromise;
const loadKeys = () =>
  (keysPromise ??= Promise.all(
    data.pgp.map(async (meta) => ({
      meta,
      key: await openpgp.readKey({ armoredKey: await (await fetch("/" + meta.file)).text() }),
    })),
  ));

// ------------------------------------------------------------------ lookups

const hex = (s) => s.replace(/^0x/i, "").replace(/[\s:]/g, "").toUpperCase();
const group4 = (fp) => fp.match(/.{1,4}/g).join(" ");
const CAPS = { s: "signing", e: "encryption", a: "authentication", c: "certification" };

function findPgp(id) {
  // id: full fingerprint (40) or key ID (16 / 8 hex), primary or subkey
  for (const k of data.pgp) {
    if (k.fpr.endsWith(id)) return { k, part: "main key" };
    for (const s of k.subkeys)
      if (s.fpr.endsWith(id))
        return { k, part: [...s.caps].map((c) => CAPS[c]).filter(Boolean).join("/") + " part" };
  }
  return null;
}

const STATUS = {
  current: ["ok", "in use"],
  revoked: ["warn", "retired"],
  retired: ["warn", "retired"],
  compromised: ["bad", "compromised"],
};

function statusLine(status, revoked) {
  if (status === "current") return "I'm still using it.";
  if (status === "compromised") return "Its private key was exposed. Don't trust anything signed with it.";
  return `I've retired it${revoked ? ` (${revoked})` : ""}. Things it signed before then are still genuine; don't encrypt to it.`;
}

const pk = (x) => (x && x.private_key ? "Private key: " + x.private_key : "");

// ------------------------------------------------------------------ output

function show(level, title, ...lines) {
  const box = $("result");
  box.className = "result " + level;
  box.replaceChildren();
  const h = document.createElement("h3");
  h.textContent = title;
  box.append(h);
  for (const l of lines.filter(Boolean)) {
    const p = document.createElement("p");
    p.textContent = l;
    box.append(p);
  }
  box.hidden = false;
}

const mine = (k, part) =>
  `${k.title}${part && part !== "main key" ? `, ${part}` : ""} · ${group4(k.fpr)}`;

// ------------------------------------------------------------------ PGP signatures

async function verifyPgp(message, signature) {
  const keys = await loadKeys();
  const res = await openpgp.verify({
    message,
    signature,
    verificationKeys: keys.map((k) => k.key),
    expectSigned: false,
  });
  if (!res.signatures.length) return show("bad", "No signature found", "This doesn't contain a PGP signature.");

  const s = res.signatures[0];
  const keyId = s.keyID.toHex().toUpperCase();
  const hit = findPgp(keyId);
  let created;
  try {
    created = (await s.signature).packets[0].created;
  } catch {}
  const when = created ? `Signed ${created.toLocaleString()}.` : "";

  if (!hit)
    return show("bad", "Not signed by me",
      `It's signed by key ${group4(keyId)}, which isn't one of mine.`);

  try {
    await s.verified;
  } catch (err) {
    if (/revoked/i.test(err.message))
      return show("warn", "Made with a key I've retired",
        mine(hit.k, hit.part), when, statusLine(hit.k.status, hit.k.revoked), pk(hit.k),
        "Your copy of the key says it was revoked, so this can't be confirmed here.");
    return show("bad", "Signature doesn't match",
      "It claims to be from " + mine(hit.k, hit.part) + ", but the content was changed after signing or the signature isn't genuine.",
      "If you pasted text, try the original file instead: copying can change spacing or line endings.");
  }

  const [level] = STATUS[hit.k.status];
  const title = { ok: "Valid signature from me", warn: "Valid signature from an older key of mine", bad: "Signed with a compromised key" }[level];
  show(level, title, mine(hit.k, hit.part), when, statusLine(hit.k.status, hit.k.revoked), pk(hit.k));
}

// ------------------------------------------------------------------ certificates

function pemToDer(pem) {
  const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function checkCert(der) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
  const sha256 = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const c = data.x509.find((x) => x.sha256 === sha256);
  if (!c)
    return show("bad", "Not one of my certificates",
      "It doesn't match any certificate I've published. A certificate with my name on it isn't necessarily mine.");
  const [level, word] = STATUS[c.status];
  show(level, { ok: "That's my certificate", warn: "That's an older certificate of mine", bad: "That certificate was compromised" }[level], c.title, `Valid ${c.not_before} to ${c.not_after}.`, statusLine(c.status), pk(c));
}

// ------------------------------------------------------------------ fingerprints

async function sshFingerprint(blob) {
  const raw = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  return "SHA256:" + btoa(String.fromCharCode(...d)).replace(/=+$/, "");
}

function checkFingerprint(input) {
  const h = hex(input);
  if (!/^[0-9A-F]+$/.test(h)) return false;

  if (h.length === 8)
    return show("warn", "Too short to check safely",
      "8-character key IDs are easy to fake. Compare the full 40-character fingerprint instead.",
      findPgp(h) ? `It does match ${findPgp(h).k.title}, for what that's worth.` : ""), true;

  const cert = data.x509.find((c) => c.sha256 === h || c.sha1 === h);
  if (cert) {
    const [level, word] = STATUS[cert.status];
    return show(level, `That's my certificate (${word})`, cert.title,
      `${h.length === 64 ? "SHA-256" : "SHA-1"} fingerprint matches.`, statusLine(cert.status), pk(cert)), true;
  }
  if (h.length === 40 || h.length === 16) {
    const hit = findPgp(h);
    if (hit) {
      const [level, word] = STATUS[hit.k.status];
      return show(level, `That's my PGP key (${word})`, mine(hit.k, hit.part),
        h.length === 16 ? "That's a key ID; the full fingerprint is safer to compare." : "",
        statusLine(hit.k.status, hit.k.revoked), pk(hit.k)), true;
    }
  }
  if ([8, 16, 40, 64].includes(h.length))
    return show("bad", "Not one of mine", "That fingerprint doesn't match any key or certificate I use or have used."), true;
  return false;
}

// ------------------------------------------------------------------ dispatcher

let fileBytes = null; // set when a binary file was dropped/chosen
let pendingSig = null; // detached signature waiting for its content

async function check() {
  const text = $("input").value.trim();
  $("signed-wrap").hidden = true;

  try {
    if (fileBytes && !text) return await checkBinary(fileBytes);
    if (!text) return show("", "Nothing to check", "Paste something or drop a file first.");

    if (text.includes("-----BEGIN PGP SIGNED MESSAGE-----"))
      return await verifyPgp(await openpgp.readCleartextMessage({ cleartextMessage: text }));

    if (text.includes("-----BEGIN PGP SIGNATURE-----"))
      return await detached(await openpgp.readSignature({ armoredSignature: text }));

    if (text.includes("-----BEGIN PGP MESSAGE-----")) {
      const msg = await openpgp.readMessage({ armoredMessage: text });
      if (msg.getEncryptionKeyIDs().length)
        return show("", "That's an encrypted message",
          "Only the person it was encrypted to can read it, so there's nothing to check here.");
      return await verifyPgp(msg);
    }

    if (text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
      return checkKey(await openpgp.readKey({ armoredKey: text }));

    if (text.includes("-----BEGIN CERTIFICATE-----")) return await checkCert(pemToDer(text));

    const ssh = text.match(/^(ssh-[a-z0-9-]+|ecdsa-[a-z0-9-]+)\s+([A-Za-z0-9+/=]+)/);
    if (ssh) {
      return ssh[2] === data.ssh.blob
        ? show("ok", "That's my SSH key", data.ssh.fingerprint)
        : show("bad", "Not my SSH key", `My SSH key's fingerprint is ${data.ssh.fingerprint}.`);
    }
    if (/^SHA256:/.test(text))
      return text === data.ssh.fingerprint
        ? show("ok", "That's my SSH key's fingerprint", data.ssh.line)
        : show("bad", "Not my SSH key", `My SSH key's fingerprint is ${data.ssh.fingerprint}.`);

    // age public keys (post-quantum ones wrap across lines when pasted, so
    // compare with whitespace removed).
    if (/^age1/.test(text)) {
      const key = text.replace(/\s+/g, "");
      const i = (data.age?.keys ?? []).findIndex((k) => k.recipient === key);
      return i >= 0
        ? show("ok", "That's one of my backup encryption keys", `${data.age.title}, key ${i + 1} of ${data.age.keys.length}.`,
            `Private key: ${data.age.keys[i].private_key}`)
        : show("bad", "Not one of my age keys", "It doesn't match any of my backup encryption keys.");
    }

    if (checkFingerprint(text)) return;

    show("", "Not sure what that is",
      "Try a PGP signature or signed message, a public key, a certificate, an SSH key, or a fingerprint.");
  } catch (err) {
    show("bad", "Couldn't read that", "It looks damaged or incomplete. (" + err.message + ")");
  }
}

function checkKey(key) {
  const fpr = key.getFingerprint().toUpperCase();
  const hit = findPgp(fpr);
  if (!hit || hit.k.fpr !== fpr)
    return show("bad", "Not one of my PGP keys",
      `Its fingerprint is ${group4(fpr)}, which doesn't match any key I use or have used.`);
  const [level, word] = STATUS[hit.k.status];
  show(level, `That's my PGP key (${word})`, mine(hit.k), statusLine(hit.k.status, hit.k.revoked), pk(hit.k));
}

async function detached(signature) {
  pendingSig = signature;
  const content = $("signed").value;
  const file = $("signed-file").files[0];
  if (!content && !file) {
    $("signed-wrap").hidden = false;
    $("result").hidden = true;
    return;
  }
  $("signed-wrap").hidden = false;
  const message = file
    ? await openpgp.createMessage({ binary: new Uint8Array(await file.arrayBuffer()) })
    : await openpgp.createMessage({ text: content });
  return verifyPgp(message, signature);
}

async function checkBinary(bytes) {
  if (bytes[0] === 0x30) return checkCert(bytes); // DER certificate (ASN.1 SEQUENCE)
  try {
    return await detached(await openpgp.readSignature({ binarySignature: bytes }));
  } catch {}
  try {
    return checkKey(await openpgp.readKey({ binaryKey: bytes }));
  } catch {}
  try {
    return await verifyPgp(await openpgp.readMessage({ binaryMessage: bytes }));
  } catch {}
  show("", "Not sure what that file is",
    "Try a .asc or .sig signature, a .crt certificate, or a public key. For a signed PDF, open it in Acrobat (see Signed PDFs below).");
}

// ------------------------------------------------------------------ wiring

async function takeFile(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const asText = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  if (/^\s*(-----BEGIN|ssh-|ecdsa-|SHA256:)/.test(asText)) {
    $("input").value = asText;
    fileBytes = null;
  } else {
    $("input").value = "";
    $("input").placeholder = `Checking ${file.name}`;
    fileBytes = bytes;
  }
  $("signed").value = "";
  $("signed-file").value = "";
  check();
}

// Wire up the checker (it was removed above if the key is revoked).
if (!revoked) {
  $("checker").addEventListener("submit", (e) => {
    e.preventDefault();
    check();
  });
  $("input").addEventListener("input", () => (fileBytes = null));
  $("file").addEventListener("change", (e) => e.target.files[0] && takeFile(e.target.files[0]));
  $("signed-file").addEventListener("change", () => pendingSig && detached(pendingSig).catch((e) => show("bad", "Couldn't read that", e.message)));

  const drop = $("input").closest(".drop");
  for (const ev of ["dragenter", "dragover"])
    drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.add("dragging")));
  for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, () => drop.classList.remove("dragging"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) takeFile(f);
  });
}
