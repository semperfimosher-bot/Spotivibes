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
  
function getArtistsFromSong(song) {
  const artistText = String(song.artist || "Unknown Artist");

  return artistText
    .split(/,|&| x | X | with | feat\.|featuring| ft\./i)
    .map(a => a.trim())
    .filter(Boolean)
    .filter(a => a.length > 1);
}

async function loadSongs() {
  await loadConfig();

  const data = await apiFetch("/api/songs?limit=1000");

  if (!data?.songs) {
    document.getElementById("songList").innerHTML =
      "Failed to load songs";
    return;
  }

  const allArtists = {};

  data.songs.forEach(song => {
    getArtistsFromSong(song).forEach(artist => {
      if (!allArtists[artist]) allArtists[artist] = [];
      allArtists[artist].push(song);
    });
  });

 const artists = Object.keys(allArtists)
  .sort((a, b) => a.localeCompare(b));

  document.getElementById("songList").innerHTML =
    artists.map((artist, index) => `
      <div class="artistFolder">
        <div class="artistFolderHeader" data-folder="${index}">
          📁 ${artist}
          <span>${allArtists[artist].length} song(s)</span>
        </div>

        <div class="artistFolderSongs hidden" id="folder-${index}">
          ${allArtists[artist]
            .sort((a, b) => a.title.localeCompare(b.title))
            .map(song => `
              <div class="row">
                <div>${song.title} - ${song.artist}</div>
                <div class="deleteBtn" data-song-id="${song.id}">−</div>
              </div>
            `).join("")}
        </div>
      </div>
    `).join("");

  document.querySelectorAll(".artistFolderHeader")
    .forEach(folder => {
      folder.addEventListener("click", () => {
        document
          .getElementById(`folder-${folder.dataset.folder}`)
          .classList.toggle("hidden");
      });
    });
}

    async function loadDuplicates() {
  const folder = document.getElementById("duplicateFolder");
  if (!folder) return;

  try {
    const data = await apiFetch("/api/admin/duplicates");

    const duplicates = data.duplicates || [];

    if (!duplicates.length) {
      folder.innerHTML = "";
      return;
    }

    folder.innerHTML = `
      <div class="duplicateFolder">
       <div class="duplicateFolderHeader" id="duplicateFolderHeader">
  <span>📁 DUPLICATES</span>

  <span>
    ${duplicates.length} item(s)
    
    <button id="deleteAllDuplicatesBtn" class="deleteAllDuplicatesBtn">
  Delete All
</button>

      Delete All
    </button>
  </span>
</div>

        <div class="duplicateFolderSongs hidden" id="duplicateFolderSongs">
          ${duplicates.map(d => `
            <div class="row">
              <div>
                <strong>${d.duplicate_title} - ${d.duplicate_artist}</strong>

                <div class="duplicateInfo">
                  Keeping: ${d.original_title} - ${d.original_artist}
                  <br>
                  Reason: ${d.reason}
                </div>
              </div>

              <button class="deleteDuplicateBtn"
                      data-duplicate-id="${d.id}">
                Delete
              </button>
            </div>
          `).join("")}
        </div>
      </div>
    `;

    document.getElementById("duplicateFolderHeader")
      ?.addEventListener("click", () => {
        document
          .getElementById("duplicateFolderSongs")
          ?.classList.toggle("hidden");
      });

    document.querySelectorAll(".deleteDuplicateBtn")
  .forEach(btn => {
    btn.addEventListener("click", async () => {
      const duplicateId = btn.getAttribute("data-duplicate-id");

      if (!duplicateId) {
        alert("Missing duplicate id.");
        return;
      }

      try {
        await apiFetch(`/api/admin/duplicates/${duplicateId}`, {
          method: "DELETE",
          credentials: "include"
        });

        await loadDuplicates();
        await loadSongs();

      } catch (err) {
        alert(err.message || "Failed to delete duplicate");
      }
    });
  });

  } catch (err) {
    console.warn("Load duplicates failed:", err.message);
  }

  document.getElementById("deleteAllDuplicatesBtn")
  ?.addEventListener("click", async (e) => {
    e.stopPropagation();

    try {
      const data = await apiFetch("/api/admin/duplicates", {
        method: "DELETE",
        credentials: "include"
      });

      alert(`Deleted ${data.deleted} duplicate(s).`);

      await loadDuplicates();
      await loadSongs();

    } catch (err) {
      alert(err.message || "Failed to delete all duplicates");
    }
  });
}

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

    const splitPhrase =
  message.includes("Suggested albums to consider uploading:")
    ? "Suggested albums to consider uploading:"
    : message.includes("Suggested artists to consider uploading:")
      ? "Suggested artists to consider uploading:"
      : "Suggested songs to consider uploading:";

const [header, ...rest] = message.split(splitPhrase);

const hasSuggestions = rest.length > 0;

const suggestions = hasSuggestions
  ? `${splitPhrase}\n${rest.join(splitPhrase)}`.trim()
  : "";

    if (!hasSuggestions) {
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

<button class="deleteNotificationBtn"
        data-notification-id="${n.id}">
  Delete
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

document.querySelectorAll(".deleteNotificationBtn")
  .forEach(btn => {
    btn.addEventListener("click", async () => {
      if (!confirm("Delete this suggestion notification?")) return;

      try {
        await apiFetch(`/api/notifications/${btn.dataset.notificationId}`, {
          method: "DELETE",
          credentials: "include"
        });

        await loadNotifications();
      } catch (err) {
        alert(err.message || "Failed to delete notification");
      }
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

  document.getElementById("scanDuplicatesBtn")
  ?.addEventListener("click", async () => {
    if (!confirm("Scan library for duplicates?")) return;

    try {
      const data = await apiFetch("/api/admin/scan-duplicates", {
        method: "POST",
        credentials: "include"
      });

      alert(`Found ${data.count} duplicate candidate(s).`);

      await loadDuplicates();
    } catch (err) {
      alert(err.message || "Duplicate scan failed");
    }
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

  setInterval(loadUploadStatus, 2000);

  window.addEventListener("focus", verifyAdminAccess);

  loadUploadStatus();
  loadSongs();
  loadDuplicates();
  loadNotifications();
 
})();