// Commentaires partagés de la carte clients (D1, liaison « DB »).
// La carte est protégée par Cloudflare Access : l'auteur vient de l'e-mail Access.
const STATUTS = ["Décédé", "Déménagé", "Pas intéressé", "À rappeler", "RDV pris", "Client signé", "Faux numéro", "—", ""];
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
let ready = false;
async function init(db) {
  if (ready) return;
  await db.prepare("CREATE TABLE IF NOT EXISTS carte_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, cle TEXT NOT NULL, statut TEXT, texte TEXT, auteur TEXT, cree_le TEXT)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS carte_notes_cle ON carte_notes(cle)").run();
  ready = true;
}
function who(request) {
  return request.headers.get("Cf-Access-Authenticated-User-Email") || null;
}
export async function onRequestGet({ request, env }) {
  if (!env.DB) return json({ erreur: "Base non reliée" }, 503);
  if (!who(request)) return json({ erreur: "Accès non authentifié" }, 401);
  await init(env.DB);
  const { results } = await env.DB.prepare("SELECT cle, statut, texte, auteur, cree_le FROM carte_notes ORDER BY id").all();
  return json({ notes: results });
}
export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ erreur: "Base non reliée" }, 503);
  const email = who(request);
  if (!email) return json({ erreur: "Accès non authentifié" }, 401);
  const o = request.headers.get("Origin");
  if (o && o !== new URL(request.url).origin) return json({ erreur: "Origine refusée" }, 403);
  await init(env.DB);
  let b = {};
  try { b = await request.json(); } catch {}
  const cle = String(b.cle || "").slice(0, 40), statut = String(b.statut || ""), texte = String(b.texte || "").trim().slice(0, 1000);
  if (!cle || !STATUTS.includes(statut) || (!statut && !texte)) return json({ erreur: "Commentaire invalide" }, 400);
  const auteur = email.split("@")[0];
  const cree_le = new Date().toISOString().replace("T", " ").slice(0, 16);
  await env.DB.prepare("INSERT INTO carte_notes (cle, statut, texte, auteur, cree_le) VALUES (?, ?, ?, ?, ?)").bind(cle, statut, texte, auteur, cree_le).run();
  return json({ ok: true, note: { cle, statut, texte, auteur, cree_le } });
}
