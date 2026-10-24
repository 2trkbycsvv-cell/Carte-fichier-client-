// Relais PVGIS (Commission européenne) pour le simulateur
export async function onRequestGet({ request }) {
  const q = new URL(request.url).searchParams;
  const num = (k, min, max) => { const v = parseFloat(q.get(k)); return Number.isFinite(v) && v >= min && v <= max ? v : null; };
  const lat = num('lat', 41, 52), lon = num('lon', -6, 10), angle = num('angle', 0, 90), aspect = num('aspect', -180, 180);
  if (lat === null || lon === null || angle === null || aspect === null) {
    return Response.json({ error: 'Paramètres invalides' }, { status: 400 });
  }
  const params = `lat=${lat}&lon=${lon}&peakpower=1&loss=14&angle=${angle}&aspect=${aspect}&outputformat=json`;
  for (const v of ['v5_3', 'v5_2']) {
    try {
      const r = await fetch(`https://re.jrc.ec.europa.eu/api/${v}/PVcalc?${params}`, { cf: { cacheTtl: 2592000, cacheEverything: true } });
      if (!r.ok) continue;
      const d = await r.json();
      return Response.json(
        { E_y: d.outputs.totals.fixed.E_y, monthly: d.outputs.monthly.fixed.map(m => m.E_m), source: 'PVGIS ' + v.replace('_', '.') },
        { headers: { 'Cache-Control': 'public, max-age=2592000' } }
      );
    } catch (e) {}
  }
  return Response.json({ error: 'PVGIS indisponible' }, { status: 502 });
}
