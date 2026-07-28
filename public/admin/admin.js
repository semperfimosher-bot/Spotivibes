let currentAdminPage = "library";
let activityLoading = false;

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
  currentAdminPage = page;

  if (page === "notifications") loadNotifications();
  if (page === "activity") loadActivity({ markRead: true });
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

/* VISITOR + LOGIN ACTIVITY */
function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatActivityTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : date.toLocaleString();
}

function getActivityTitle(activity) {
  if (activity.event_type === "LOGIN_SUCCESS") {
    return activity.is_bot ? "Bot login succeeded" : "Login succeeded";
  }

  if (activity.event_type === "LOGIN_FAILED") {
    return activity.is_bot ? "Bot login failed" : "Login failed";
  }

  if (activity.event_type === "REGISTER_SUCCESS") {
    return activity.is_bot ? "Bot account registered" : "Account registered";
  }

  if (activity.event_type === "PAGE_VIEW") {
    if (activity.is_bot) return "Bot visited the app";
    if (activity.user_id) return "Signed-in user visited the app";
    return "Anonymous visitor opened the app";
  }

  return String(activity.event_type || "Activity")
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, letter => letter.toUpperCase());
}

function getActivityIdentity(activity) {
  const fullName = [activity.first_name, activity.last_name]
    .filter(Boolean)
    .join(" ")
    .trim();

  const parts = [];

  if (fullName) parts.push(`<strong>${escapeHtml(fullName)}</strong>`);
  if (activity.email) parts.push(escapeHtml(activity.email));

  if (parts.length) return parts.join(" · ");
  return activity.is_bot ? "Automated visitor" : "Anonymous visitor";
}

function renderActivity(activity) {
  const tags = [];

  if (activity.is_bot) {
    tags.push('<span class="activity-tag bot">Bot</span>');
  }

  if (activity.event_type === "LOGIN_FAILED") {
    tags.push('<span class="activity-tag failed">Failed</span>');
  }

  if (!activity.read_at) {
    tags.push('<span class="activity-tag">New</span>');
  }

  const requestLine = [activity.method, activity.path]
    .filter(Boolean)
    .map(escapeHtml)
    .join(" ");

  const details = [];
  const metadata = activity.metadata && typeof activity.metadata === "object"
    ? activity.metadata
    : {};

  if (requestLine) details.push(requestLine);
  if (activity.ip_address) details.push(`Network: ${escapeHtml(activity.ip_address)}`);
  if (metadata.country) details.push(`Country: ${escapeHtml(metadata.country)}`);
  if (metadata.referrerOrigin) {
    details.push(`Referrer: ${escapeHtml(metadata.referrerOrigin)}`);
  }
  if (metadata.pageTitle) details.push(`Page: ${escapeHtml(metadata.pageTitle)}`);
  if (metadata.reason) {
    const reasonLabels = {
      unknown_account: "Unknown account",
      incorrect_password: "Incorrect password",
      rate_limited: "Rate limited"
    };

    details.push(`Reason: ${escapeHtml(reasonLabels[metadata.reason] || metadata.reason)}`);
  }
  if (activity.user_agent) details.push(`Client: ${escapeHtml(activity.user_agent)}`);

  return `
    <article class="activity-item ${activity.read_at ? "" : "unread"}">
      <div class="activity-item-header">
        <div>
          <div class="activity-title">${escapeHtml(getActivityTitle(activity))}</div>
          <div>${tags.join("")}</div>
        </div>
        <div class="activity-time">${escapeHtml(formatActivityTime(activity.created_at))}</div>
      </div>

      <div class="activity-identity">${getActivityIdentity(activity)}</div>

      <div class="activity-details">
        ${details.map(detail => `<div>${detail}</div>`).join("")}
      </div>
    </article>
  `;
}

async function loadUnreadActivityCount() {
  try {
    const data = await apiFetch("/api/admin/activity/unread-count", {
      credentials: "include",
      cache: "no-store"
    });

    const count = Number(data?.count || 0);
    const badge = document.getElementById("activityUnreadBadge");

    if (badge) {
      badge.textContent = count > 999 ? "999+" : String(count);
      badge.classList.toggle("hidden", count === 0);
    }

    document.title = count > 0
      ? `(${count}) Admin Panel`
      : "Admin Panel";
  } catch (err) {
    console.warn("Activity count failed:", err.message);
  }
}

async function markAllActivityRead(ids = []) {
  await apiFetch("/api/admin/activity/mark-read", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ ids })
  });
}

async function loadActivity({ markRead = false } = {}) {
  const list = document.getElementById("activityList");
  const summary = document.getElementById("activitySummary");
  const filter = document.getElementById("activityFilter")?.value || "all";

  if (!list || !summary || activityLoading) return;

  activityLoading = true;
  summary.textContent = "Loading activity…";

  try {
    const data = await apiFetch(
      `/api/admin/activity?limit=100&filter=${encodeURIComponent(filter)}`,
      {
        credentials: "include",
        cache: "no-store"
      }
    );

    const activities = data?.activities || [];
    const total = Number(data?.total || 0);

    summary.textContent = total === 1
      ? "1 matching activity record"
      : `${total} matching activity records`;

    list.innerHTML = activities.length
      ? activities.map(renderActivity).join("")
      : '<div class="empty-state">No activity matches this filter.</div>';

    if (markRead && activities.length) {
      try {
        await markAllActivityRead(activities.map(activity => activity.id));
      } catch (err) {
        console.warn("Mark activity read failed:", err.message);
      }
    }

    await loadUnreadActivityCount();
  } catch (err) {
    summary.textContent = "Activity could not be loaded.";
    list.innerHTML = `<div class="empty-state">${escapeHtml(err.message || "Failed to load activity")}</div>`;
  } finally {
    activityLoading = false;
  }
}

document.getElementById("activityFilter")
  ?.addEventListener("change", () => loadActivity({ markRead: true }));

document.getElementById("refreshActivityBtn")
  ?.addEventListener("click", () => loadActivity({ markRead: true }));

document.getElementById("markActivityReadBtn")
  ?.addEventListener("click", async () => {
    try {
      await markAllActivityRead();
      await loadActivity();
    } catch (err) {
      alert(err.message || "Failed to mark activity as read");
    }
  });

document.getElementById("clearActivityBtn")
  ?.addEventListener("click", async () => {
    if (!confirm("Clear all visitor and login activity?")) return;

    try {
      await apiFetch("/api/admin/activity", {
        method: "DELETE",
        credentials: "include"
      });

      await loadActivity();
    } catch (err) {
      alert(err.message || "Failed to clear activity");
    }
  });

async function pollActivity() {
  await loadUnreadActivityCount();

  if (currentAdminPage === "activity" && document.visibilityState === "visible") {
    await loadActivity({ markRead: true });
  }
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
  setInterval(pollActivity, 10000);

  window.addEventListener("focus", verifyAdminAccess);

  loadUploadStatus();
  loadSongs();
  loadDuplicates();
  loadNotifications();
  loadUnreadActivityCount();
 
})();