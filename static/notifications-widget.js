document.addEventListener("DOMContentLoaded", function () {
  const badges = document.querySelectorAll("[data-notifications-badge]");
  if (!badges.length) return;

  fetch("/web/notifications/unread-count", {
    credentials: "same-origin",
    headers: { "Accept": "application/json" },
  })
    .then((r) => (r.ok ? r.json() : { unread: 0 }))
    .then((data) => {
      const unread = Number(data.unread || 0);
      badges.forEach((badge) => {
        if (unread > 0) {
          badge.textContent = unread > 99 ? "99+" : String(unread);
          badge.classList.remove("d-none");
        } else {
          badge.textContent = "";
          badge.classList.add("d-none");
        }
      });
    })
    .catch(() => {
      // ignore widget errors
    });
});
