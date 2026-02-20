(function () {
  const btn = document.getElementById("enable-push-btn");
  const testBtn = document.getElementById("test-push-btn");

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
      if (testBtn) testBtn.style.display = "none";
      return;
    }

    const swRegistration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });

    let keyResp;
    try {
      keyResp = await fetch("/api/push/public-key", { credentials: "same-origin" });
    } catch (_) {
      if (btn) btn.style.display = "none";
      if (testBtn) testBtn.style.display = "none";
      return;
    }

    if (!keyResp.ok) {
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Push не настроен";
        btn.title = "Нужно задать VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY и VAPID_SUBJECT";
      }
      if (testBtn) testBtn.disabled = true;
      return;
    }

    const keyData = await keyResp.json();
    const publicKey = keyData.publicKey;

    if (testBtn) {
      testBtn.addEventListener("click", async function () {
        const prev = testBtn.textContent;
        testBtn.disabled = true;
        testBtn.textContent = "Отправка...";
        try {
          await postJson("/api/push/test", {});
          testBtn.textContent = "Отправлено";
        } catch (err) {
          testBtn.textContent = "Ошибка теста";
        } finally {
          setTimeout(function () {
            testBtn.textContent = prev || "Тест push";
            if (btn && btn.disabled) testBtn.disabled = false;
          }, 1200);
        }
      });
    }

    let subscription = await swRegistration.pushManager.getSubscription();
    if (subscription) {
      await postJson("/api/push/subscribe", subscription.toJSON());
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Уведомления включены";
      }
      if (testBtn) testBtn.disabled = false;
      return;
    }

    if (!btn) return;
    if (testBtn) testBtn.disabled = true;

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
        if (testBtn) testBtn.disabled = false;
      } catch (err) {
        btn.textContent = "Ошибка push";
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initPush().catch(function () {
      if (btn) btn.style.display = "none";
      if (testBtn) testBtn.style.display = "none";
    });
  });
})();
