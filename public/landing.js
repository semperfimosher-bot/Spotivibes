let deferredPrompt = null;

window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  deferredPrompt = event;

  console.log("PWA install prompt saved.");

  const installBtn = document.getElementById("installBtn");
  if (installBtn) {
    installBtn.disabled = false;
    installBtn.style.opacity = "1";
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const installBtn = document.getElementById("installBtn");

  if (!installBtn) {
    console.warn("installBtn not found");
    return;
  }

  installBtn.addEventListener("click", async () => {
    console.log("Install button clicked", deferredPrompt);

    if (!deferredPrompt) {
      alert("Install is not ready yet. Refresh once, wait a few seconds, then try again.");
      return;
    }

    deferredPrompt.prompt();

    const choice = await deferredPrompt.userChoice;
    console.log("Install choice:", choice);

    deferredPrompt = null;
  });
});