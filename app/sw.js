// Service worker de l'appli DCRF : notifications
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) { d = { title: "DCRF", body: event.data ? event.data.text() : "" }; }
  const title = d.title || "DCRF";
  const opts = { body: d.body || "", tag: d.tag || undefined, renotify: !!d.tag, icon: "/icon-192.png", badge: "/icon-192.png", data: { url: d.url || "/" } };
  event.waitUntil((async () => {
    await self.registration.showNotification(title, opts);
    const list = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    list.forEach((c) => c.postMessage({ type: "push", tag: d.tag || "" }));
  })());
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = new URL((event.notification.data && event.notification.data.url) || "/", self.location.origin).href;
  event.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of list) {
      if (new URL(c.url).origin === self.location.origin) { await c.focus(); try { await c.navigate(url); } catch (e) {} return; }
    }
    await self.clients.openWindow(url);
  })());
});
