(function () {
  const btn = document.getElementById("enable-push-btn");

  function urlBase64ToUint8Array(base64String) {
    const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
  }

  async function postJson(url, data) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      credentials: "same-origin",
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  }

  async function initPush() {
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
      if (btn) btn.style.display = "none";
      return;
    }

    const swRegistration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });

    let keyResp;
    try {
      keyResp = await fetch("/api/push/public-key", { credentials: "same-origin" });
    } catch (_) {
      if (btn) btn.style.display = "none";
      return;
    }

    if (!keyResp.ok) {
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Push off";
      }
      return;
    }

    const keyData = await keyResp.json();
    const publicKey = keyData.publicKey;

    let subscription = await swRegistration.pushManager.getSubscription();
    if (subscription) {
      await postJson("/api/push/subscribe", subscription.toJSON());
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Уведомления включены";
      }
      return;
    }

    if (!btn) return;

    btn.addEventListener("click", async function () {
      try {
        const permission = await Notification.requestPermission();
        if (permission !== "granted") {
          btn.textContent = "Разрешите уведомления";
          return;
        }

        subscription = await swRegistration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(publicKey),
        });

        await postJson("/api/push/subscribe", subscription.toJSON());
        btn.disabled = true;
        btn.textContent = "Уведомления включены";
      } catch (err) {
        btn.textContent = "Ошибка push";
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initPush().catch(function () {
      if (btn) btn.style.display = "none";
    });
  });
})();
