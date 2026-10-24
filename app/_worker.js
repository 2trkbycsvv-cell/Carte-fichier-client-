// Appli DCRF — serveur (Cloudflare Pages, mode avancé).
// Sert les fichiers de l'appli et l'API /api/* avec la base D1 (liaison « DB »).
// Réglage obligatoire dans Cloudflare : variable secrète TEAM_PASSWORD = mot de passe de l'équipe.

/* ================= Règles métier (identiques à l'appli) ================= */
const ROLES_ACTIFS = ["admin", "vendeur", "apporteur", "pose"];
const TYPES = {
  vente: { label: "Vente signée", peut: ["admin", "vendeur", "apporteur"], notif: { roles: ["admin", "pose"], vendeur: true } },
  annulation: { label: "Annulation", peut: ["admin", "vendeur", "apporteur"], notif: { roles: ["admin", "pose"], vendeur: true } },
  financement_ok: { label: "Financement accepté", peut: ["admin"], notif: { roles: ["admin", "pose"], vendeur: true } },
  financement_refus: { label: "Financement refusé", peut: ["admin"], notif: { roles: ["admin"], vendeur: true } },
  rdv: { label: "Nouveau RDV", peut: ["admin"], notif: { roles: [], vendeur: true } },
  pose_planifiee: { label: "Pose planifiée", peut: ["admin", "pose"], notif: { roles: ["admin"], vendeur: true } },
  pose_terminee: { label: "Pose terminée", peut: ["admin", "pose"], notif: { roles: ["admin"], vendeur: true } },
  sav: { label: "Problème chantier / SAV", peut: ["admin", "pose", "vendeur"], notif: { roles: ["admin", "pose"], vendeur: true } },
  encaissement: { label: "Encaissement", peut: ["admin"], notif: { roles: ["admin"], vendeur: false } },
  info: { label: "Message à l'équipe", peut: ["admin"], notif: { roles: ["admin", "vendeur", "apporteur", "pose"], vendeur: false } },
};
const VISIBLES_POSE = ["vente", "annulation", "financement_ok", "pose_planifiee", "pose_terminee", "sav", "info"];
const EMOJIS = ["👍", "🔥", "😂", "💪", "🏆"];
const DIRECTION = [
  ["t.hoarau.dcrf@gmail.com", "Tristan", "admin"],
  ["diagnostique.hf@gmail.com", "Elias", "admin"],
];

const SEL = "RENSRi1hcHBsaS12MQ"; // sel PBKDF2 (public)
const ITERATIONS = 10000;
const COOKIE = "dcrf_s";
const SESSION_JOURS = 180;

/* ================= Utilitaires ================= */
const enc = new TextEncoder();
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers } });
const err = (msg, status = 400) => json({ erreur: msg }, status);
const nowSQL = () => new Date().toISOString().replace("T", " ").slice(0, 19);
const clean = (v, max = 200) => (v == null ? null : String(v).trim().slice(0, max) || null);
const normEmail = (e) => String(e || "").trim().toLowerCase().slice(0, 160);
const okEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
function b64u(buf) { const b = new Uint8Array(buf); let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function unb64u(s) { s = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); }
const concat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
async function sha256hex(s) { const h = await crypto.subtle.digest("SHA-256", enc.encode(s)); return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, "0")).join(""); }
function safeEq(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
function cookieOf(req, name) { const m = (req.headers.get("Cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)")); return m ? m[1] : null; }

/* ================= Base de données ================= */
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, nom TEXT, role TEXT NOT NULL DEFAULT 'attente', chat_notif INTEGER NOT NULL DEFAULT 1, cree_le TEXT, vu_le TEXT)`,
  `CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE NOT NULL, email TEXT NOT NULL, nom TEXT, appareil TEXT, statut TEXT NOT NULL, cree_le TEXT, vu_le TEXT)`,
  `CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, client TEXT, ville TEXT, montant REAL, organisme TEXT, date_evt TEXT, commentaire TEXT, vendeur_email TEXT, vendeur_nom TEXT, auteur_email TEXT, auteur_nom TEXT, cree_le TEXT)`,
  `CREATE TABLE IF NOT EXISTS chat (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, nom TEXT, type TEXT NOT NULL DEFAULT 'msg', texte TEXT, defi_titre TEXT, defi_fin TEXT, gagnant_email TEXT, gagnant_nom TEXT, cree_le TEXT)`,
  `CREATE TABLE IF NOT EXISTS chat_reactions (msg_id INTEGER, email TEXT, emoji TEXT, PRIMARY KEY (msg_id, email, emoji))`,
  `CREATE TABLE IF NOT EXISTS chat_participants (msg_id INTEGER, email TEXT, nom TEXT, PRIMARY KEY (msg_id, email))`,
  `CREATE TABLE IF NOT EXISTS subs (endpoint TEXT PRIMARY KEY, email TEXT, p256dh TEXT, auth TEXT, appareil TEXT, cree_le TEXT)`,
  `CREATE TABLE IF NOT EXISTS config (cle TEXT PRIMARY KEY, valeur TEXT)`,
  `CREATE TABLE IF NOT EXISTS echecs (cle TEXT, ts INTEGER)`,
  `CREATE INDEX IF NOT EXISTS ev_vendeur ON events(vendeur_email)`,
  `CREATE INDEX IF NOT EXISTS sub_email ON subs(email)`,
];
let schemaOk = false;
async function ensureSchema(db) {
  if (schemaOk) return;
  await db.batch(SCHEMA.map((s) => db.prepare(s)));
  await db.batch(DIRECTION.map(([e, n, r]) => db.prepare("INSERT OR IGNORE INTO users (email, nom, role, cree_le) VALUES (?, ?, ?, ?)").bind(e, n, r, nowSQL())));
  schemaOk = true;
}

/* ================= Mot de passe ================= */
let expectedCache = null;
async function expectedProof(password) {
  if (expectedCache && expectedCache.p === password) return expectedCache.v;
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: unb64u(SEL), iterations: ITERATIONS, hash: "SHA-256" }, key, 256);
  expectedCache = { p: password, v: b64u(bits) };
  return expectedCache.v;
}

/* ================= Session ================= */
async function getSession(req, env) {
  const tok = cookieOf(req, COOKIE);
  if (!tok) return null;
  const row = await env.DB.prepare(
    `SELECT s.id, s.statut, s.appareil, s.vu_le AS s_vu, u.email, u.nom, u.role, u.chat_notif, u.vu_le
     FROM sessions s JOIN users u ON u.email = s.email WHERE s.token = ?`).bind(await sha256hex(tok)).first();
  if (!row) return null;
  const t = Date.now();
  if (!row.s_vu || t - Date.parse(row.s_vu.replace(" ", "T") + "Z") > 10 * 60e3) {
    const n = nowSQL();
    await env.DB.batch([
      env.DB.prepare("UPDATE sessions SET vu_le = ? WHERE id = ?").bind(n, row.id),
      env.DB.prepare("UPDATE users SET vu_le = ? WHERE email = ?").bind(n, row.email),
    ]);
  }
  return row;
}
const actif = (me) => me && me.statut === "ok" && ROLES_ACTIFS.includes(me.role);

/* ================= Notifications (Web Push, RFC 8291 + VAPID) ================= */
async function vapidKeys(env) {
  const r = await env.DB.prepare("SELECT valeur FROM config WHERE cle = 'vapid'").first();
  if (r) return JSON.parse(r.valeur);
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = b64u(concat(new Uint8Array([4]), unb64u(jwk.x), unb64u(jwk.y)));
  const v = { jwk, pub };
  await env.DB.prepare("INSERT OR IGNORE INTO config (cle, valeur) VALUES ('vapid', ?)").bind(JSON.stringify(v)).run();
  const again = await env.DB.prepare("SELECT valeur FROM config WHERE cle = 'vapid'").first();
  return JSON.parse(again.valeur);
}
async function vapidHeader(endpoint, keys) {
  const aud = new URL(endpoint).origin;
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "mailto:t.hoarau.dcrf@gmail.com" })));
  const key = await crypto.subtle.importKey("jwk", keys.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(head + "." + body));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${keys.pub}`;
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
async function encryptPayload(sub, text) {
  const uaPub = unb64u(sub.p256dh), auth = unb64u(sub.auth);
  const as = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", as.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(auth, shared, concat(enc.encode("WebPush: info\0"), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, concat(enc.encode(text), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return concat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}
async function sendPush(env, sub, payload, keys) {
  try {
    const body = await encryptPayload(sub, JSON.stringify(payload));
    const r = await fetch(sub.endpoint, {
      method: "POST",
      headers: { Authorization: await vapidHeader(sub.endpoint, keys), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "high" },
      body,
    });
    if (r.status === 404 || r.status === 410) await env.DB.prepare("DELETE FROM subs WHERE endpoint = ?").bind(sub.endpoint).run();
    return r.ok;
  } catch (e) { return false; }
}
// Envoie à une liste d'e-mails ; renvoie le nombre de personnes ayant au moins un appareil
async function notify(env, emails, payload) {
  emails = [...new Set(emails.filter(Boolean))];
  if (!emails.length) return 0;
  const q = emails.map(() => "?").join(",");
  const { results } = await env.DB.prepare(`SELECT * FROM subs WHERE email IN (${q})`).bind(...emails).all();
  if (!results.length) return 0;
  const keys = await vapidKeys(env);
  await Promise.all(results.map((s) => sendPush(env, s, payload, keys)));
  return new Set(results.map((s) => s.email)).size;
}
async function emailsByRoles(env, roles) {
  if (!roles.length) return [];
  const q = roles.map(() => "?").join(",");
  const { results } = await env.DB.prepare(`SELECT email FROM users WHERE role IN (${q})`).bind(...roles).all();
  return results.map((r) => r.email);
}

function eur(n) { return n == null || n === "" || isNaN(n) ? "" : new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 0 }).format(Math.round(Number(n))) + " €"; }
function fmtDateEvt(s) {
  const m = String(s || "").match(/^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}))?/);
  if (!m) return "";
  const j = ["dim.", "lun.", "mar.", "mer.", "jeu.", "ven.", "sam."][new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])).getUTCDay()];
  return `${j} ${m[3]}/${m[2]}` + (m[4] ? ` à ${+m[4]}h${m[5]}` : "");
}
function notifText(e) {
  const t = TYPES[e.type] || { label: e.type };
  const title = e.type === "info" ? `Message de ${e.auteur_nom || "la direction"}` : t.label + (e.client ? ` · ${e.client}` : "");
  const bits = e.type === "info" ? [e.commentaire] : [e.vendeur_nom, e.organisme, e.montant ? eur(e.montant) : "", e.date_evt ? fmtDateEvt(e.date_evt) : "", e.ville, e.commentaire];
  return { title, body: bits.filter(Boolean).join(" · ").slice(0, 240) };
}

/* ================= Routes ================= */
async function readBody(req) { try { return await req.json(); } catch { return {}; } }

const routes = {
  "GET /api/connexion": async () => json({ sel: SEL, iterations: ITERATIONS }),

  "POST /api/connexion": async ({ req, env }) => {
    if (!env.TEAM_PASSWORD) return err("Le mot de passe de l'équipe n'est pas encore réglé dans Cloudflare.", 503);
    const b = await readBody(req);
    const email = normEmail(b.email), nom = clean(b.nom, 80), appareil = clean(b.appareil, 40) || "Navigateur";
    if (!okEmail(email) || !nom) return err("Indique ton nom et une adresse e-mail valide.");
    const ip = req.headers.get("CF-Connecting-IP") || "?";
    const since = Date.now() - 15 * 60e3;
    const fails = await env.DB.prepare("SELECT COUNT(*) AS n FROM echecs WHERE (cle = ? OR cle = ?) AND ts > ?").bind("ip:" + ip, "em:" + email, since).first();
    if (fails.n >= 8) return err("Trop d'essais. Réessaie dans 15 minutes.", 429);
    const good = await expectedProof(env.TEAM_PASSWORD);
    if (!safeEq(String(b.preuve || ""), good)) {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO echecs (cle, ts) VALUES (?, ?), (?, ?)").bind("ip:" + ip, Date.now(), "em:" + email, Date.now()),
        env.DB.prepare("DELETE FROM echecs WHERE ts < ?").bind(Date.now() - 24 * 3600e3),
      ]);
      return err("Mot de passe incorrect.", 401);
    }
    let user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
    if (!user) {
      await env.DB.prepare("INSERT INTO users (email, nom, role, cree_le) VALUES (?, ?, 'attente', ?)").bind(email, nom, nowSQL()).run();
      user = { email, nom, role: "attente" };
    } else if (!user.nom) {
      await env.DB.prepare("UPDATE users SET nom = ? WHERE email = ?").bind(nom, email).run();
    }
    const statut = user.role === "attente" ? "attente" : "ok";
    const tok = b64u(crypto.getRandomValues(new Uint8Array(32)));
    await env.DB.prepare("INSERT INTO sessions (token, email, nom, appareil, statut, cree_le, vu_le) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(await sha256hex(tok), email, nom, appareil, statut, nowSQL(), nowSQL()).run();
    if (statut === "attente") {
      const admins = await emailsByRoles(env, ["admin"]);
      await notify(env, admins, { title: "Demande d'accès à l'appli", body: `${nom} (${email}) · ${appareil}`, tag: "acces", url: "/#equipe" });
    }
    return json({ ok: true, connexion: statut }, 200, { "Set-Cookie": `${COOKIE}=${tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_JOURS * 86400}` });
  },

  "DELETE /api/connexion": async ({ req, env }) => {
    const tok = cookieOf(req, COOKIE);
    if (tok) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(await sha256hex(tok)).run();
    return json({ ok: true }, 200, { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
  },

  "GET /api/moi": async ({ env, me }) => {
    const base = { email: me.email, nom: me.nom, role: me.role, connexion: me.statut, chat_notif: me.chat_notif };
    if (!actif(me)) return json(base);
    const [eq, ap, ch, keys] = await Promise.all([
      env.DB.prepare("SELECT email, nom, role FROM users WHERE role IN ('admin','vendeur','apporteur','pose') ORDER BY nom").all(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM subs WHERE email = ?").bind(me.email).first(),
      env.DB.prepare("SELECT MAX(id) AS m FROM chat").first(),
      vapidKeys(env),
    ]);
    return json({ ...base, vapidPublicKey: keys.pub, equipe: eq.results, appareils: ap.n, chatDernier: ch.m || 0 });
  },

  "POST /api/profil": async ({ req, env, me }) => {
    const nom = clean((await readBody(req)).nom, 80);
    if (!nom) return err("Indique ton nom.");
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET nom = ? WHERE email = ?").bind(nom, me.email),
      env.DB.prepare("UPDATE sessions SET nom = ? WHERE email = ?").bind(nom, me.email),
    ]);
    return json({ ok: true });
  },

  "POST /api/preferences": async ({ req, env, me }) => {
    const b = await readBody(req);
    await env.DB.prepare("UPDATE users SET chat_notif = ? WHERE email = ?").bind(b.chat_notif ? 1 : 0, me.email).run();
    return json({ ok: true });
  },

  "POST /api/abonnement": async ({ req, env, me }) => {
    const b = await readBody(req), s = b.subscription || {};
    if (!s.endpoint || !s.keys || !s.keys.p256dh || !s.keys.auth || !/^https:\/\//.test(s.endpoint)) return err("Abonnement invalide.");
    await env.DB.prepare("INSERT INTO subs (endpoint, email, p256dh, auth, appareil, cree_le) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET email = excluded.email, p256dh = excluded.p256dh, auth = excluded.auth, appareil = excluded.appareil")
      .bind(s.endpoint, me.email, s.keys.p256dh, s.keys.auth, clean(b.appareil, 40), nowSQL()).run();
    return json({ ok: true });
  },
  "DELETE /api/abonnement": async ({ req, env, me }) => {
    const b = await readBody(req);
    await env.DB.prepare("DELETE FROM subs WHERE endpoint = ? AND email = ?").bind(String(b.endpoint || ""), me.email).run();
    return json({ ok: true });
  },
  "POST /api/test-notif": async ({ env, me }) => {
    const n = await notify(env, [me.email], { title: "Test DCRF", body: "Les notifications fonctionnent sur cet appareil.", tag: "test", url: "/#reglages" });
    if (!n) return err("Aucun appareil abonné pour ton compte.");
    return json({ ok: true });
  },

  /* ---------- Fil ---------- */
  "GET /api/evenements": async ({ url, env, me }) => {
    const avant = parseInt(url.searchParams.get("avant")) || 0;
    const where = [], args = [];
    if (me.role === "pose") { where.push(`(type IN (${VISIBLES_POSE.map(() => "?").join(",")}) OR auteur_email = ?)`); args.push(...VISIBLES_POSE, me.email); }
    else if (me.role !== "admin") { where.push("(vendeur_email = ? OR auteur_email = ? OR type = 'info')"); args.push(me.email, me.email); }
    if (avant) { where.push("id < ?"); args.push(avant); }
    const { results } = await env.DB.prepare(`SELECT * FROM events ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY id DESC LIMIT 41`).bind(...args).all();
    return json({ evenements: results.slice(0, 40), suite: results.length > 40 });
  },

  "POST /api/evenements": async ({ req, env, me, ctx }) => {
    const b = await readBody(req), t = TYPES[b.type];
    if (!t) return err("Type d'événement inconnu.");
    if (!t.peut.includes(me.role)) return err("Ton rôle ne permet pas de déclarer cet événement.", 403);
    let vEmail = null, vNom = null;
    if (me.role === "admin" || me.role === "pose") {
      if (b.vendeur_email) {
        const v = await env.DB.prepare("SELECT email, nom FROM users WHERE email = ?").bind(normEmail(b.vendeur_email)).first();
        if (v) { vEmail = v.email; vNom = v.nom; }
      }
    } else { vEmail = me.email; vNom = me.nom; }
    let montant = b.montant != null && b.montant !== "" ? parseFloat(String(b.montant).replace(/\s|€/g, "").replace(",", ".")) : null;
    if (montant != null && (!isFinite(montant) || montant < 0 || montant > 1e7)) return err("Montant invalide.");
    const date = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2})?$/.test(b.date_evt || "") ? b.date_evt : null;
    const e = {
      type: b.type, client: clean(b.client, 120), ville: clean(b.ville, 80), montant, organisme: clean(b.organisme, 40), date_evt: date,
      commentaire: clean(b.commentaire, 2000), vendeur_email: vEmail, vendeur_nom: vNom, auteur_email: me.email, auteur_nom: me.nom, cree_le: nowSQL(),
    };
    if (b.type !== "info" && !e.client) return err("Indique le nom du client.");
    if (b.type === "info" && !e.commentaire) return err("Écris le message.");
    const r = await env.DB.prepare(`INSERT INTO events (type, client, ville, montant, organisme, date_evt, commentaire, vendeur_email, vendeur_nom, auteur_email, auteur_nom, cree_le)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(e.type, e.client, e.ville, e.montant, e.organisme, e.date_evt, e.commentaire, e.vendeur_email, e.vendeur_nom, e.auteur_email, e.auteur_nom, e.cree_le).run();
    e.id = r.meta.last_row_id;
    let dest = await emailsByRoles(env, t.notif.roles);
    if (t.notif.vendeur && vEmail) dest.push(vEmail);
    dest = dest.filter((x) => x !== me.email);
    const prevenus = await notify(env, dest, { ...notifText(e), tag: "evt-" + e.id, url: "/#fil" });
    return json({ ok: true, evenement: e, prevenus });
  },

  "DELETE /api/evenements": async ({ url, env, me }) => {
    const id = parseInt(url.searchParams.get("id"));
    const e = await env.DB.prepare("SELECT auteur_email FROM events WHERE id = ?").bind(id).first();
    if (!e) return err("Événement introuvable.", 404);
    if (me.role !== "admin" && e.auteur_email !== me.email) return err("Tu ne peux supprimer que ce que tu as déclaré.", 403);
    await env.DB.prepare("DELETE FROM events WHERE id = ?").bind(id).run();
    return json({ ok: true });
  },

  /* ---------- Équipe (direction) ---------- */
  "GET /api/utilisateurs": async ({ env, me }) => {
    if (me.role !== "admin") return err("Réservé à la direction.", 403);
    const { results } = await env.DB.prepare(`SELECT u.email, u.nom, u.role, u.vu_le, (SELECT COUNT(*) FROM subs s WHERE s.email = u.email) AS appareils FROM users u ORDER BY u.role = 'attente' DESC, u.nom`).all();
    return json({ utilisateurs: results });
  },
  "POST /api/utilisateurs": async ({ req, env, me }) => {
    if (me.role !== "admin") return err("Réservé à la direction.", 403);
    const b = await readBody(req), email = normEmail(b.email), role = String(b.role || "");
    if (!okEmail(email)) return err("Adresse e-mail invalide.");
    if (![...ROLES_ACTIFS, "bloque"].includes(role)) return err("Rôle invalide.");
    if (email === me.email) return err("Tu ne peux pas changer ton propre rôle.");
    const ex = await env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email).first();
    if (ex) await env.DB.prepare("UPDATE users SET role = ?, nom = COALESCE(?, nom) WHERE email = ?").bind(role, clean(b.nom, 80), email).run();
    else await env.DB.prepare("INSERT INTO users (email, nom, role, cree_le) VALUES (?, ?, ?, ?)").bind(email, clean(b.nom, 80), role, nowSQL()).run();
    if (role !== "bloque") await env.DB.prepare("UPDATE sessions SET statut = 'ok' WHERE email = ? AND statut = 'attente'").bind(email).run();
    return json({ ok: true });
  },
  "GET /api/sessions": async ({ env, me }) => {
    if (me.role !== "admin") return err("Réservé à la direction.", 403);
    const { results } = await env.DB.prepare(`SELECT s.id, s.email, COALESCE(u.nom, s.nom) AS nom, u.role, s.statut, s.appareil, s.cree_le, s.vu_le
      FROM sessions s LEFT JOIN users u ON u.email = s.email ORDER BY s.statut = 'attente' DESC, COALESCE(s.vu_le, s.cree_le) DESC LIMIT 100`).all();
    return json({ sessions: results });
  },
  "POST /api/sessions": async ({ req, env, me }) => {
    if (me.role !== "admin") return err("Réservé à la direction.", 403);
    const b = await readBody(req), id = parseInt(b.id);
    const s = await env.DB.prepare("SELECT s.*, u.role FROM sessions s LEFT JOIN users u ON u.email = s.email WHERE s.id = ?").bind(id).first();
    if (!s) return err("Connexion introuvable.", 404);
    if (b.action === "valider") {
      if (s.role === "attente") {
        if (!ROLES_ACTIFS.includes(b.role)) return err("Choisis son rôle.");
        await env.DB.prepare("UPDATE users SET role = ? WHERE email = ?").bind(b.role, s.email).run();
      }
      await env.DB.prepare("UPDATE sessions SET statut = 'ok' WHERE email = ? AND statut = 'attente'").bind(s.email).run();
      await notify(env, [s.email], { title: "Accès validé", body: "Bienvenue dans l'appli DCRF.", tag: "acces-ok", url: "/" });
    } else if (b.action === "refuser" || b.action === "deconnecter") {
      if (s.email === me.email && b.action === "deconnecter" && cookieOf(req, COOKIE) && s.token === (await sha256hex(cookieOf(req, COOKIE)))) return err("C'est l'appareil que tu utilises : passe par « Se déconnecter ».");
      await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(id).run();
    } else return err("Action inconnue.");
    return json({ ok: true });
  },

  /* ---------- Chat ---------- */
  "GET /api/chat": async ({ url, env }) => {
    const apres = parseInt(url.searchParams.get("apres")) || 0;
    let msgs;
    if (apres) msgs = (await env.DB.prepare("SELECT * FROM chat WHERE id > ? ORDER BY id LIMIT 200").bind(apres).all()).results;
    else msgs = (await env.DB.prepare("SELECT * FROM (SELECT * FROM chat ORDER BY id DESC LIMIT 150) ORDER BY id").all()).results;
    const defis = (await env.DB.prepare("SELECT * FROM chat WHERE type = 'defi' ORDER BY id DESC LIMIT 30").all()).results;
    const all = [...msgs, ...defis];
    const ids = [...new Set(all.map((m) => m.id))];
    if (ids.length) {
      const q = ids.map(() => "?").join(",");
      const [rx, pa] = await Promise.all([
        env.DB.prepare(`SELECT msg_id, email, emoji FROM chat_reactions WHERE msg_id IN (${q})`).bind(...ids).all(),
        env.DB.prepare(`SELECT msg_id, email, nom FROM chat_participants WHERE msg_id IN (${q})`).bind(...ids).all(),
      ]);
      for (const m of all) {
        m.reactions = rx.results.filter((r) => r.msg_id === m.id).map((r) => ({ email: r.email, emoji: r.emoji }));
        m.participants = pa.results.filter((r) => r.msg_id === m.id).map((r) => ({ email: r.email, nom: r.nom }));
      }
    }
    return json({ messages: msgs, defis, suite: false });
  },

  "POST /api/chat": async ({ req, env, me }) => {
    const b = await readBody(req);
    const others = async () => (await env.DB.prepare("SELECT email FROM users WHERE role IN ('admin','vendeur','apporteur','pose') AND chat_notif = 1 AND email != ?").bind(me.email).all()).results.map((r) => r.email);
    if (b.action) {
      const id = parseInt(b.id);
      const m = await env.DB.prepare("SELECT * FROM chat WHERE id = ?").bind(id).first();
      if (!m) return err("Message introuvable.", 404);
      if (b.action === "reaction") {
        if (!EMOJIS.includes(b.emoji)) return err("Réaction inconnue.");
        const ex = await env.DB.prepare("SELECT 1 FROM chat_reactions WHERE msg_id = ? AND email = ? AND emoji = ?").bind(id, me.email, b.emoji).first();
        if (ex) await env.DB.prepare("DELETE FROM chat_reactions WHERE msg_id = ? AND email = ? AND emoji = ?").bind(id, me.email, b.emoji).run();
        else await env.DB.prepare("INSERT INTO chat_reactions (msg_id, email, emoji) VALUES (?, ?, ?)").bind(id, me.email, b.emoji).run();
      } else if (b.action === "participer") {
        if (m.type !== "defi" || m.gagnant_email) return err("Ce défi n'est plus ouvert.");
        const ex = await env.DB.prepare("SELECT 1 FROM chat_participants WHERE msg_id = ? AND email = ?").bind(id, me.email).first();
        if (ex) await env.DB.prepare("DELETE FROM chat_participants WHERE msg_id = ? AND email = ?").bind(id, me.email).run();
        else await env.DB.prepare("INSERT INTO chat_participants (msg_id, email, nom) VALUES (?, ?, ?)").bind(id, me.email, me.nom).run();
      } else if (b.action === "gagnant") {
        if (m.type !== "defi") return err("Ce n'est pas un défi.");
        if (m.email !== me.email && me.role !== "admin") return err("Seul celui qui a lancé le défi peut désigner le gagnant.", 403);
        const w = await env.DB.prepare("SELECT email, nom FROM users WHERE email = ?").bind(normEmail(b.email)).first();
        if (!w) return err("Personne introuvable.");
        await env.DB.prepare("UPDATE chat SET gagnant_email = ?, gagnant_nom = ? WHERE id = ?").bind(w.email, w.nom, id).run();
        await notify(env, [...(await others()), me.email].filter((x) => x !== me.email), { title: "🏆 Défi remporté", body: `${w.nom} remporte « ${m.defi_titre} »`, tag: "defi-" + id, url: "/#chat" });
      } else if (b.action === "supprimer") {
        if (m.email !== me.email && me.role !== "admin") return err("Tu ne peux supprimer que tes messages.", 403);
        await env.DB.batch([
          env.DB.prepare("DELETE FROM chat WHERE id = ?").bind(id),
          env.DB.prepare("DELETE FROM chat_reactions WHERE msg_id = ?").bind(id),
          env.DB.prepare("DELETE FROM chat_participants WHERE msg_id = ?").bind(id),
        ]);
      } else return err("Action inconnue.");
      return json({ ok: true });
    }
    if (b.defi) {
      const titre = clean(b.defi.titre, 120);
      if (!titre) return err("Écris le défi.");
      const fin = /^\d{4}-\d{2}-\d{2}$/.test(b.defi.fin || "") ? b.defi.fin : null;
      const r = await env.DB.prepare("INSERT INTO chat (email, nom, type, texte, defi_titre, defi_fin, cree_le) VALUES (?, ?, 'defi', ?, ?, ?, ?)").bind(me.email, me.nom, clean(b.defi.texte, 1000), titre, fin, nowSQL()).run();
      await notify(env, await others(), { title: `Défi lancé par ${me.nom}`, body: titre, tag: "defi-" + r.meta.last_row_id, url: "/#chat" });
      return json({ ok: true, id: r.meta.last_row_id });
    }
    const texte = clean(b.texte, 2000);
    if (!texte) return err("Message vide.");
    const r = await env.DB.prepare("INSERT INTO chat (email, nom, type, texte, cree_le) VALUES (?, ?, 'msg', ?, ?)").bind(me.email, me.nom, texte, nowSQL()).run();
    await notify(env, await others(), { title: me.nom || "Chat DCRF", body: texte.slice(0, 200), tag: "chat", url: "/#chat" });
    return json({ ok: true, id: r.meta.last_row_id });
  },
};

const PUBLIC = new Set(["GET /api/connexion", "POST /api/connexion", "DELETE /api/connexion"]);
const EN_ATTENTE_OK = new Set(["GET /api/moi"]);

/* ================= Relais PVGIS (simulateur solaire) ================= */
async function pvgis(url) {
  const q = url.searchParams;
  const num = (k, min, max) => { const v = parseFloat(q.get(k)); return Number.isFinite(v) && v >= min && v <= max ? v : null; };
  const lat = num("lat", 41, 52), lon = num("lon", -6, 10), angle = num("angle", 0, 90), aspect = num("aspect", -180, 180);
  if (lat === null || lon === null || angle === null || aspect === null) return err("Paramètres invalides");
  const params = `lat=${lat}&lon=${lon}&peakpower=1&loss=14&angle=${angle}&aspect=${aspect}&outputformat=json`;
  for (const v of ["v5_3", "v5_2"]) {
    try {
      const r = await fetch(`https://re.jrc.ec.europa.eu/api/${v}/PVcalc?${params}`, { cf: { cacheTtl: 2592000, cacheEverything: true } });
      if (!r.ok) continue;
      const d = await r.json();
      return json({ E_y: d.outputs.totals.fixed.E_y, monthly: d.outputs.monthly.fixed.map((m) => m.E_m), source: "PVGIS " + v.replace("_", ".") });
    } catch (e) {}
  }
  return err("PVGIS indisponible", 502);
}

/* ================= Point d'entrée ================= */
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try {
      if (url.pathname === "/api/pvgis") return await pvgis(url);
      if (!env.DB) return err("Base de données non reliée (liaison « DB » manquante dans Cloudflare).", 503);
      if (req.method !== "GET") {
        const o = req.headers.get("Origin");
        if (o && o !== url.origin) return err("Origine refusée.", 403);
      }
      await ensureSchema(env.DB);
      const key = `${req.method} ${url.pathname}`;
      const h = routes[key];
      if (!h) return err("Introuvable.", 404);
      let me = null;
      if (!PUBLIC.has(key)) {
        me = await getSession(req, env);
        if (!me) return err("Connexion nécessaire.", 401);
        if (!EN_ATTENTE_OK.has(key) && !actif(me)) return err("Ton accès n'est pas encore validé.", 403);
      }
      return await h({ req, env, ctx, url, me });
    } catch (e) {
      return err("Erreur du serveur : " + (e && e.message ? e.message : e), 500);
    }
  },
};
