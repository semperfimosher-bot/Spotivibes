async function verifyAdminAccess() {
  try {
    await loadConfig();

    await apiFetch("/api/admin/check", {
      credentials: "include",
      cache: "no-store"
    });

    document.getElementById("adminContent").classList.remove("hidden");
    document.getElementById("adminBlocked").classList.add("hidden");

    return true;
  } catch {
    document.getElementById("adminContent").classList.add("hidden");
    document.getElementById("adminBlocked").classList.remove("hidden");

    return false;
  }
}

function show(page) {
  document.querySelectorAll(".main > div").forEach(d => d.classList.add("hidden"));
  document.getElementById(page).classList.remove("hidden");

  if (page === "notifications") loadNotifications();
}

document.querySelectorAll("[data-page]").forEach(btn => {
  btn.addEventListener("click", () => {
    show(btn.dataset.page);
  });
});

document.getElementById("uploadSongsBtn")
  ?.addEventListener("click", uploadFiles);

document.getElementById("uploadBackgroundBtn")
  ?.addEventListener("click", uploadBackground);

  document.getElementById("discoverArtistsBtn")
  ?.addEventListener("click", async () => {
    try {
      const data = await apiFetch("/api/admin/discover-artists", {
        method: "POST",
        credentials: "include"
      });

      alert(`Generated ${data.count} missing artist suggestions.`);

      await loadNotifications();

    } catch (err) {
      alert(err.message || "Failed to generate artist suggestions");
    }
  });

document.getElementById("songList")
  ?.addEventListener("click", (e) => {
    const deleteBtn = e.target.closest("[data-song-id]");
    if (!deleteBtn) return;

    deleteSong(deleteBtn.dataset.songId);
  });
  
async function loadSongs() {
  await loadConfig();

  const data = await apiFetch("/api/songs");

  if (!data?.songs) {
    document.getElementById("songList").innerHTML = "Failed to load songs";
    return;
  }

  const sorted = data.songs.sort((a, b) =>
    a.title.localeCompare(b.title)
  );

  document.getElementById("songList").innerHTML =
    sorted.map(s => `
      <div class="row">
        <div>${s.title} - ${s.artist}</div>
        <div class="deleteBtn" data-song-id="${s.id}">−</div>
      </div>
    `).join("");
}

/* DELETE SONG */
function deleteSong(id) {
  if (!confirm("Delete this song?")) return;

  apiFetch("/api/songs/" + id, { method: "DELETE" })
    .then(() => loadSongs());
}

/* UPLOAD SONGS */
async function uploadFiles() {
  await loadConfig();

  const fileInput = document.getElementById("fileInput");
  const files = Array.from(fileInput.files);

  if (!files.length) {
    alert("No files selected");
    return;
  }

  const batchSize = 20;
  let uploaded = 0;

  for (let i = 0; i < files.length; i += batchSize) {
    const batch = files.slice(i, i + batchSize);
    const formData = new FormData();

    batch.forEach(file => {
      formData.append("songs", file);
    });

    let data;

    try {
      data = await apiFetch("/api/upload-files", {
        method: "POST",
        body: formData
      });
    } catch (err) {
      alert(err.message || "Upload failed");
      return;
    }

    if (!data?.success) {
      alert(`Upload failed at song ${uploaded + 1}`);
      return;
    }

    const failed = data.results?.filter(r => !r.success) || [];
    const successCount = data.results?.filter(r => r.success).length || 0;

    uploaded += successCount;

    if (failed.length) {
      console.warn("Failed uploads:", failed);
    }
  }

  alert(`Upload complete. ${uploaded} song(s) processed.`);

  fileInput.value = "";

  await loadSongs();
  await loadUploadStatus();
}

/* 🔥 FIXED BACKGROUND UPLOAD */
async function uploadBackground() {
  await loadConfig();

  const file = document.getElementById("bgFile").files[0];
  const status = document.getElementById("bgStatus");

  if (!file) {
    status.innerText = "No file selected";
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  status.innerText = "Uploading...";

  let data;

try {
  data = await apiFetch("/api/upload-bg", {
    method: "POST",
    body: formData
  });
} catch (err) {
  status.innerText = err.message || "Upload failed";
  return;
}

  if (!data?.success) {
    status.innerText = data?.error || "Upload failed";
    return;
  }

  status.innerText = "Upload successful!";
}

/* NOTIFICATIONS */
async function loadNotifications() {
  await loadConfig();

  const data = await apiFetch("/api/notifications");

  if (!data?.notifications) {
    document.getElementById("notifList").innerHTML =
      "Failed to load notifications";
    return;
  }

 document.getElementById("notifList").innerHTML =
  data.notifications.map((n, index) => {
    const message = String(n.message || "");

    const [header, ...rest] =
      message.includes("Suggested artists to consider uploading:")
  ? message.split("Suggested artists to consider uploading:")
  : message.split("Suggested songs to consider uploading:");

    const suggestions =
      rest.join("").trim();

    if (!suggestions) {
      return `
        <div class="row">
          <div class="notification-message">
            ${header.replace(/\n/g, "<br>")}
          </div>
        </div>
      `;
    }

    return `
      <div class="row">
        <div class="notification-message">

          <div class="notifHeader">
      ${header.replace(/\n/g, "<br>")}
          </div>

          <button class="viewSuggestionsBtn"
                  data-suggestion-id="${index}">
            View suggestions
          </button>

          <div id="suggestions-${index}"
               class="suggestionsBox hidden">
            ${suggestions.replace(/\n/g, "<br>")}
          </div>
        </div>
      </div>
    `;
  }).join("");

document.querySelectorAll(".viewSuggestionsBtn")
  .forEach(btn => {
    btn.addEventListener("click", () => {
      const box =
        document.getElementById(
          `suggestions-${btn.dataset.suggestionId}`
        );

      box.classList.toggle("hidden");

      btn.innerText =
        box.classList.contains("hidden")
          ? "View suggestions"
          : "Hide suggestions";
    });
  });
}

document.getElementById("deleteAllContentBtn")
  ?.addEventListener("click", async () => {
    const code = prompt("Enter delete code:");

    if (code !== "2009") {
      alert("Wrong code.");
      return;
    }

    const data = await apiFetch("/api/admin/delete-all-content", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "include",
      body: JSON.stringify({ code })
    });

    if (!data?.success) {
      alert(data?.error || "Delete failed");
      return;
    }

    alert("All content deleted.");
    location.reload();
  });

  async function loadUploadStatus() {
  const summary = document.getElementById("uploadStatusSummary");
  const list = document.getElementById("uploadStatusList");

  if (!summary || !list) return;

  try {
    const data = await apiFetch("/api/upload-status");
    const jobs = data.jobs || [];

    const uploading = jobs.filter(j => j.status === "uploading").length;
    const complete = jobs.filter(j => j.status === "complete").length;
    const failed = jobs.filter(j => j.status === "failed").length;

    summary.innerHTML = `
      Uploading: ${uploading} · Complete: ${complete} · Failed: ${failed}
    `;

    list.innerHTML = jobs.map(job => `
      <div class="upload-job ${job.status}">
        <strong>${job.filename}</strong>
        <span>${job.status}</span>
        ${job.error ? `<small>${job.error}</small>` : ""}
      </div>
    `).join("");

  } catch (err) {
    console.warn("Upload status failed:", err.message);
  }
}

(async () => {
  const allowed = await verifyAdminAccess();
  if (!allowed) return;

  setInterval(async () => {
    const stillAllowed = await verifyAdminAccess();
    if (!stillAllowed) return;

    loadUploadStatus();
  }, 2000);

  loadUploadStatus();
  loadSongs();
  loadNotifications();
})();