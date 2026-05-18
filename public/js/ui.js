// ==========================
// SEARCH INTELLIGENCE LAYER
// ==========================
let searchCache = new Map();
let activeDropdownIndex = -1;
let currentDropdownItems = [];

// ==========================
// VIEW SYSTEM
// ==========================
function showView(page) {
  const views = {
    stats: document.getElementById("statsView"),
    home: document.getElementById("homeView"),
    library: document.getElementById("libraryView"),
    queue: document.getElementById("queueView"),
    mobileSearch: document.getElementById("mobileSearchView"),
  };

  if (page === "search") {
    page = "home";

    setTimeout(() => {
      document.getElementById("searchBar")?.focus();
    }, 0);
  }

  Object.values(views).forEach(v => {
    if (v) v.classList.add("hidden");
  });

  if (views[page]) {
    views[page].classList.remove("hidden");
  }

  updateActiveTab?.(page);
}

// ==========================
// INIT
// ==========================
function initUI() {

  // default page
  showView("home");

 const searchBar = document.getElementById("searchBar");
const mobileSearchBar = document.getElementById("mobileSearchBar");

if (searchBar) {
 searchBar.addEventListener(
  "input",
  debounce(handleSearch, 120)
);

  searchBar?.addEventListener("keydown", (e) => {
    // keep your existing desktop keydown code here
  });
}

mobileSearchBar?.addEventListener(
  "input",
  debounce(handleMobileSearch, 120)
);

  searchBar?.addEventListener("keydown", (e) => {

    const dropdown =
      document.getElementById("searchDropdown");

    const isOpen =
      dropdown &&
      dropdown.style.display === "block";

    if (isOpen && e.key === "ArrowDown") {
      e.preventDefault();

      activeDropdownIndex =
        Math.min(
          activeDropdownIndex + 1,
          currentDropdownItems.length - 1
        );

      updateDropdownHighlight();
      return;
    }

    if (isOpen && e.key === "ArrowUp") {
      e.preventDefault();

      activeDropdownIndex =
        Math.max(activeDropdownIndex - 1, 0);

      updateDropdownHighlight();
      return;
    }

    if (e.key === "Enter") {
      e.preventDefault();

      const query = searchBar.value.trim();
      if (!query) return;

      if (isOpen && activeDropdownIndex >= 0) {
        selectDropdownItem(
          currentDropdownItems[activeDropdownIndex]
        );
        return;
      }

      handleSearch({
        target: { value: query }
      });
    }
  });
}

// ==========================
// DEBOUNCE
// ==========================
function debounce(fn, delay = 200) {
  let timeout;

  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), delay);
  };
}

// ==========================
// CONFIG
// ==========================
const MIN_SEARCH_LENGTH = 1;
const RECENT_SEARCHES_KEY = "spotivibes_recent_searches";

// ==========================
// DROPDOWN CONTROL
// ==========================
function closeSearchDropdown() {
  const dropdown = document.getElementById("searchDropdown");
  if (!dropdown) return;

  dropdown.innerHTML = "";
  dropdown.classList.add("hidden");
  dropdown.style.display = "none";

  currentDropdownItems = [];
  activeDropdownIndex = -1;
}

function openSearchDropdown() {
  const dropdown = document.getElementById("searchDropdown");
  if (!dropdown) return;

  dropdown.classList.remove("hidden");
  dropdown.style.display = "block";
}

// ==========================
// RECENT SEARCHES
// ==========================
function getRecentSearches() {
  try {
    return JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY)) || [];
  } catch {
    return [];
  }
}

function saveRecentSearch(query) {
  if (!query) return;

  let searches = getRecentSearches();
  searches = searches.filter(s => s !== query);

  searches.unshift(query);
  searches = searches.slice(0, 8);

  localStorage.setItem(
    RECENT_SEARCHES_KEY,
    JSON.stringify(searches)
  );
}

// ==========================
// FUZZY MATCH
// ==========================
function fuzzyMatchScore(query, text) {
  if (!query || !text) return 0;

  query = query.toLowerCase().trim();
  text = text.toLowerCase().trim();

  if (text === query) return 100;
  if (text.startsWith(query)) return 90;
  if (text.includes(query)) return 75;

  const words = text.split(/\s+/);

  for (const word of words) {
    if (word.startsWith(query)) return 85;
    if (word.includes(query)) return 70;
  }

  const distance = levenshteinDistance(query, text);
  const maxLength = Math.max(query.length, text.length);

  const similarity =
    1 - distance / maxLength;

  if (similarity > 0.7) {
    return Math.round(similarity * 65);
  }

  let score = 0;
  let qi = 0;

  for (let i = 0; i < text.length && qi < query.length; i++) {
    if (text[i] === query[qi]) {
      score += 8;
      qi++;
    }
  }

  return score;
}

function levenshteinDistance(a, b) {
  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

// ==========================
// RANKING
// ==========================
function rankSongs(query, songs) {
  return songs
    .map(song => {
      const text = `${song.title} ${song.artist}`;
      return {
        ...song,
        score: fuzzyMatchScore(query, text)
      };
    })
    .sort((a, b) => b.score - a.score);
}

// ==========================
// LIVE SEARCH
// ==========================

async function handleMobileSearch(e) {
  const query = e.target.value.trim();
  const results = document.getElementById("mobileSearchResults");

  if (!results) return;

  results.innerHTML = "";

  if (!query) return;

  const res = await apiFetch(
    `/api/smart-search?q=${encodeURIComponent(query)}`
  );

  if (!res) return;

  if (res.playlists?.length) {
    res.playlists.forEach(playlist => {
      results.appendChild(createGeneratedPlaylistCard(playlist));
    });

    highlightCurrentSong();
    return;
  }

  if (res.songs?.length) {
    res.songs.forEach(song => {
      results.appendChild(createSongRow(song));
    });

    highlightCurrentSong();
    return;
  }

  results.innerHTML =
    "<p style='color:#b3b3b3'>No results found.</p>";
}

// ==========================
// DROPDOWN RENDER
// ==========================
function renderSearchDropdown(songs = []) {
  const dropdown = document.getElementById("searchDropdown");
  if (!dropdown) return;

  dropdown.innerHTML = "";

  if (!songs.length) {
    closeSearchDropdown();
    return;
  }

  currentDropdownItems = songs.slice(0, 8);
  activeDropdownIndex = -1;

  currentDropdownItems.forEach(song => {
    const item = document.createElement("div");
    item.className = "search-item";
    item.textContent = `${song.title} — ${song.artist}`;

    item.onmousedown = (e) => {
      e.preventDefault();
      selectDropdownItem(song);
    };

    dropdown.appendChild(item);
  });

  openSearchDropdown();
}

// ==========================
// SELECT ITEM
// ==========================
function selectDropdownItem(song) {
  saveRecentSearch(song.title);
  closeSearchDropdown();
  playSong(song.id);
}

// ==========================
// HIGHLIGHT UI
// ==========================
function updateDropdownHighlight() {
  const items = document.querySelectorAll(".search-item");

  items.forEach((el, i) => {
    el.style.background =
      i === activeDropdownIndex
        ? "rgba(255,255,255,0.15)"
        : "transparent";
  });
}

// ==========================
// SEARCH HANDLER
// ==========================
async function handleSearch(e) {
  closeSearchDropdown();

  const query = e.target.value.trim();

  if (!query) {
    showView("home");
    renderHome();
    return;
  }

  saveRecentSearch(query);

  const res = await apiFetch(`/api/smart-search?q=${encodeURIComponent(query)}`);

  if (!res) return;

  renderSmartSearchResults(res);
}

// ==========================
// SEARCH RESULTS
// ==========================
function renderSmartSearchResults(data) {
  const top = document.getElementById("topSongsGrid");
  const list = document.getElementById("recentGrid");

  if (!top || !list) return;

  closeSearchDropdown();
  showView("home");

  top.innerHTML = "";
  list.innerHTML = "";

  if (data.playlists?.length) {
    data.playlists.forEach(playlist => {
      top.appendChild(createGeneratedPlaylistCard(playlist));
    });
  }

  if (data.songs?.length) {
    data.songs.forEach(song => {
      list.appendChild(createSongRow(song));
    });
  }

  if (!data.playlists?.length && !data.songs?.length) {
    
    list.innerHTML = "<p style='color:#b3b3b3'>No results found.</p>";
  }
}

function renderPlaylistSongs(playlist) {
  const top = document.getElementById("topSongsGrid");
  const list = document.getElementById("recentGrid");

  if (!top || !list) return;

  showView("home");

  top.innerHTML = "";
  list.innerHTML = "";

  playlist.songs.forEach(song => {
    list.appendChild(createSongRow(song));
  });

  highlightCurrentSong();
}

// ==========================
// COMPONENTS
// ==========================
function createGeneratedPlaylistCard(playlist) {
  const row = document.createElement("div");
  row.className = "row generated-playlist-row";

  row.innerHTML = `
   ${renderPlaylistArt(playlist)} 

    <div style="flex:1">
      <div style="color:white">
        ${playlist.name}
      </div>

      <div style="color:#b3b3b3;font-size:12px">
        ${playlist.type} playlist · ${playlist.songs.length} songs
      </div>
    </div>

    <button class="playlist-add-btn">
      Add
    </button>
  `;

  row.addEventListener("click", () => {
    renderPlaylistSongs(playlist);
  });
}

  const addBtn = row.querySelector(".playlist-add-btn");

  addBtn?.addEventListener("click", async (e) => {
  e.stopPropagation();

  const res = await apiFetch("/api/playlists/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: playlist.name,
      query: playlist.name,
      songs: playlist.songs
    })
  });

  if (res?.success) {
    await loadSavedPlaylists();
    addBtn.innerText = "Added";
  }
});

function renderPlaylistArt(playlist) {
  const covers = getPlaylistArt(playlist);

  if (!covers.length) {
    return `<div class="sidebar-library-thumb playlist-thumb"></div>`;
  }

  if (covers.length < 4) {
    return `
      <div
        class="sidebar-library-thumb playlist-single-art"
        style="background-image:url('${covers[0]}')"
      ></div>
    `;
  }

  return `
    <div class="playlist-art-grid">
      ${covers.map(url => `
        <div style="background-image:url('${url}')"></div>
      `).join("")}
    </div>
  `;
}

function getPlaylistArt(playlist) {
  return playlist.songs
    ?.map(song => song.coverUrl)
    .filter(Boolean)
    .slice(0, 4) || [];
}

function createSidebarPlaylistRow(playlist) {

  const row = document.createElement("div");
  row.className = "sidebar-library-row";

  row.innerHTML = `
   ${renderPlaylistArt(playlist)}

    <div class="sidebar-library-info">
      <div>${playlist.name}</div>
      <span>${playlist.songs.length} songs</span>
    </div>

    <button class="sidebar-library-more">
      ⋮
    </button>

    <div class="sidebar-library-menu hidden">

      <button class="remove-playlist-btn">
        Remove from Library
      </button>

      <button class="download-playlist-btn">
        Download Songs
      </button>

    </div>
  `;

  row.addEventListener("click", (e) => {
    if (
      e.target.closest(".sidebar-library-more") ||
      e.target.closest(".sidebar-library-menu")
    ) {
      return;
    }

    renderPlaylistSongs(playlist);
    showView("home");
  });

  const moreBtn = row.querySelector(".sidebar-library-more");
  const menu = row.querySelector(".sidebar-library-menu");

  moreBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    menu.classList.toggle("hidden");
  });

  row.querySelector(".remove-playlist-btn")
  ?.addEventListener("click", () => {

    state.libraryPlaylists =
      state.libraryPlaylists.filter(
        p => p.name !== playlist.name
      );

    state.customPlaylists =
      state.customPlaylists.filter(
        p => p.name !== playlist.name
      );

    localStorage.setItem(
      "libraryPlaylists",
      JSON.stringify(state.libraryPlaylists)
    );

    localStorage.setItem(
      "customPlaylists",
      JSON.stringify(state.customPlaylists)
    );

    renderLibrary();
  });

  row.querySelector(".download-playlist-btn")
    ?.addEventListener("click", () => {
      playlist.songs.forEach(song => {
        downloadSong(song);
      });

      menu.classList.add("hidden");
    });

  return row;
}
function createSongCard(song) {
  const card = document.createElement("div");
  card.className = "card";
  card.dataset.id = song.id;

  card.innerHTML = `

    <div 
     class="thumb" 
     style="background-image: url('${song.coverUrl || ""}')"
    ></div>

    <div class="song-card-footer">
      <div>

    <div class="song-title">
         ${song.title || "Unknown Title"}
    </div>

        <div style="color:#b3b3b3;font-size:12px">
          ${song.artist || "Unknown Album"}
        </div>
      </div>

      <button class="song-more-btn">⋯</button>
    </div>
  `;

   card.addEventListener("click", () => playSong(song.id));

  const moreBtn = card.querySelector(".song-more-btn");

  moreBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    openSongMenu(song, moreBtn);
  });

  return card;
}

function createSongRow(song) {
  const row = document.createElement("div");
  row.className = "row";
  row.dataset.id = song.id;

  row.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;flex:1">

      <div
        class="row-thumb"
        style="background-image:url('${song.coverUrl || ""}')"
      ></div>

      <div>
        <div class="song-title" style="color:#fff">
          ${song.title || "Unknown Title"}
        </div>

        <div style="color:#b3b3b3;font-size:12px">
          ${song.artist || "Unknown Artist"}
        </div>
      </div>

    </div>

    <button class="song-more-btn">⋯</button>
  `;

  row.addEventListener("click", () => playSong(song.id));

  const moreBtn = row.querySelector(".song-more-btn");

  moreBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    openSongMenu(song, moreBtn);
  });

  return row;
}

function createCompactSongRow(song) {
  const row = document.createElement("div");
  row.className = "compact-song-row";
  row.dataset.id = song.id;

  row.innerHTML = `
    <div
      class="compact-thumb"
      style="background-image:url('${song.coverUrl || ""}')"
    ></div>

    <div class="compact-info">
      <div>${song.title || "Unknown Title"}</div>
      <div>${song.artist || "Unknown Artist"}</div>
    </div>
  `;

  row.addEventListener("click", () => playSong(song.id));

  return row;
}

function createSidebarLibraryRow(song) {
  const row = document.createElement("div");
  row.className = "sidebar-library-row";
  row.dataset.id = song.id;

  row.innerHTML = `
    <div
      class="sidebar-library-thumb"
      style="background-image:url('${song.coverUrl || ""}')"
    ></div>

    <div class="sidebar-library-info">
      <div class="song-title">${song.title || "Unknown Title"}</div>
      <span>${song.artist || "Unknown Artist"}</span>
    </div>

    <button class="sidebar-library-more">
      ⋮
    </button>

    <div class="sidebar-library-menu hidden">

      <button class="remove-library-btn">
        Remove from Library
      </button>

      <a
        class="download-song-btn"
        href="${song.audioUrl}"
        download
      >
        Download
      </a>

    </div>
  `;

  row.addEventListener("click", (e) => {

    if (
      e.target.closest(".sidebar-library-more") ||
      e.target.closest(".sidebar-library-menu")
    ) {
      return;
    }

    playSong(song.id);
  });

  const moreBtn =
    row.querySelector(".sidebar-library-more");

  const menu =
    row.querySelector(".sidebar-library-menu");

  moreBtn?.addEventListener("click", (e) => {
    e.stopPropagation();

    menu.classList.toggle("hidden");
  });

  row.querySelector(".remove-library-btn")
    ?.addEventListener("click", () => {

  removeSongFromLibrary(song);
  });

  return row;
}

document.addEventListener("click", (e) => {

  const clickedMoreButton =
    e.target.closest(".sidebar-library-more");

  const clickedInsideMenu =
    e.target.closest(".sidebar-library-menu");

  if (clickedMoreButton || clickedInsideMenu) {
    return;
  }

  document
    .querySelectorAll(".sidebar-library-menu")
    .forEach(menu => {
      menu.classList.add("hidden");
  });
});

// ==========================
// RENDER FUNCTIONS
// ==========================

function renderListeningStats() {
  const list = document.getElementById("artistStatsList");
  if (!list) return;

  const stats =
    JSON.parse(localStorage.getItem("listeningStats")) || {};

  list.innerHTML = "";

  const artists = Object.keys(stats);

  if (!artists.length) {
    list.innerHTML =
      "<p style='color:#b3b3b3'>No listening stats yet.</p>";
    return;
  }

  artists.forEach(artist => {
    const totalPlays = Object.values(stats[artist])
      .reduce((sum, count) => sum + count, 0);

    const row = document.createElement("div");
    row.className = "row";

    row.innerHTML = `
      <div>
        <div style="color:white">${artist}</div>
        <div style="color:#b3b3b3;font-size:12px">
          ${totalPlays} total plays
        </div>
      </div>
    `;

    row.addEventListener("click", () => {
      renderArtistSongStats(artist);
    });

    list.appendChild(row);
  });
}

function renderArtistSongStats(artist) {
  const list = document.getElementById("artistStatsList");
  if (!list) return;

  const stats =
    JSON.parse(localStorage.getItem("listeningStats")) || {};

  const songs = stats[artist] || {};

  list.innerHTML = `
    <button id="backToArtistsBtn">← Back</button>
    <h2>${artist}</h2>
  `;

  Object.entries(songs).forEach(([title, count]) => {
    const row = document.createElement("div");
    row.className = "row";

    row.innerHTML = `
      <div>
        <div style="color:white">${title}</div>
        <div style="color:#b3b3b3;font-size:12px">
          Played ${count} time${count === 1 ? "" : "s"}
        </div>
      </div>
    `;

    list.appendChild(row);
  });

  document
    .getElementById("backToArtistsBtn")
    ?.addEventListener("click", renderListeningStats);
}
  function renderListeningStats() {
  const list = document.getElementById("artistStatsList");
  if (!list) return;

  const stats =
    JSON.parse(localStorage.getItem("listeningStats")) || {};

  list.innerHTML = "";

  const artists = Object.keys(stats);

  if (!artists.length) {
    list.innerHTML =
      "<p style='color:#b3b3b3'>No listening stats yet.</p>";
    return;
  }

  artists
  .sort((a, b) => {
    const totalA = Object.values(stats[a])
      .reduce((sum, count) => sum + count, 0);

    const totalB = Object.values(stats[b])
      .reduce((sum, count) => sum + count, 0);

    return totalB - totalA;
  })
  .forEach(artist => {

    const totalPlays = Object.values(stats[artist])
      .reduce((sum, count) => sum + count, 0);

    const row = document.createElement("div");
    row.className = "row";

    row.innerHTML = `
      <div>
        <div style="color:white">${artist}</div>
        <div style="color:#b3b3b3;font-size:12px">
          ${totalPlays} total plays
        </div>
      </div>
    `;

    row.addEventListener("click", () => {
      renderArtistSongStats(artist);
    });

    list.appendChild(row);
  });
}

function renderArtistSongStats(artist) {
  const list = document.getElementById("artistStatsList");
  if (!list) return;

  const stats =
    JSON.parse(localStorage.getItem("listeningStats")) || {};

  const songs = stats[artist] || {};

  list.innerHTML = `
    <button id="backToArtistsBtn">← Back</button>
    <h2>${artist}</h2>
  `;

  Object.entries(songs)
  .sort((a, b) => b[1] - a[1])
  .forEach(([title, count]) => {

    const row = document.createElement("div");
    row.className = "row";

    row.innerHTML = `
      <div>
        <div style="color:white">${title}</div>
        <div style="color:#b3b3b3;font-size:12px">
          Played ${count} time${count === 1 ? "" : "s"}
        </div>
      </div>
    `;

    list.appendChild(row);
  });

  document
    .getElementById("backToArtistsBtn")
    ?.addEventListener("click", renderListeningStats);
 }
function renderHome() {
  const recent = document.getElementById("recentGrid");
  const top = document.getElementById("topSongsGrid");

  if (!recent || !top) return;

  recent.innerHTML = "";
  top.innerHTML = "";

  const songs = state.songs || [];

  if (!songs.length) {
  recent.innerHTML = "<p style='color:#b3b3b3'>No songs found.</p>";
  top.innerHTML = "";
  return;
}

  songs.forEach(s => recent.appendChild(createSongCard(s)));
  songs.slice(0, 8).forEach(s => top.appendChild(createCompactSongRow(s)));

  highlightCurrentSong();
}

function renderLibrary() {
  const list = document.getElementById("libraryList");
  const sidebarList = document.getElementById("sidebarLibraryList");

  if (!list) return;

  list.innerHTML = "";
  if (sidebarList) sidebarList.innerHTML = "";

  const songs = state.library || [];
  const playlists = state.libraryPlaylists || [];
  const customPlaylists = state.customPlaylists || [];

  if (!songs.length && !playlists.length) {
    list.innerHTML = "<p style='color:#b3b3b3'>Your library is empty</p>";
  }

  customPlaylists.forEach(p => {
  if (sidebarList) {
    sidebarList.appendChild(createSidebarPlaylistRow(p));
  }

  list.appendChild(createSidebarPlaylistRow(p));
});

  playlists.forEach(p => {
    list.appendChild(createSidebarPlaylistRow(p));

    if (sidebarList) {
      sidebarList.appendChild(createSidebarPlaylistRow(p));
    }
  });

  songs.forEach(s => {
    list.appendChild(createSongRow(s));

    if (sidebarList) {
      sidebarList.appendChild(createSidebarLibraryRow(s));
    }
  });

  highlightCurrentSong();
}

function renderQueue() {
  const list = document.getElementById("queueList");
  if (!list) return;

  list.innerHTML = "";

  const idx = state.songs.findIndex(s => s.id === state.currentId);
  const queue = state.songs.slice(idx + 1, idx + 11);

  if (!queue.length) {
    list.innerHTML = "<p style='color:#b3b3b3'>Queue is empty</p>";
    return;
  }

  queue.forEach(s => list.appendChild(createSongRow(s)));
}

// ==========================
// HIGHLIGHT
// ==========================
function highlightCurrentSong() {

  document.querySelectorAll(".song-title").forEach(title => {
    title.style.color = "#fff";
    title.style.fontWeight = "400";
  });

  if (!state.currentId) return;

  document
    .querySelectorAll(".row, .card, .sidebar-library-row")
    .forEach(el => {

      if (String(el.dataset?.id) === String(state.currentId)) {

        const title = el.querySelector(".song-title");

        if (title) {
          title.style.color = "#004cff";
          title.style.fontWeight = "600";
        }
      }
    });
}

function openSongMenu(song, button) {
  closeSongMenu();

  const menu = document.createElement("div");
  menu.className = "song-menu";

  const inLibrary = state.library.some(
    s => String(s.id) === String(song.id)
  );

  const playlists = state.customPlaylists || [];

  menu.innerHTML = `
    <button class="downloadSongBtn">Download MP3</button>

    ${
      inLibrary
        ? `<button class="removeLibraryBtn">Remove from Library</button>`
        : `<button class="addLibraryBtn">Add to Library</button>`
    }

    <button class="addToPlaylistBtn">Add to Playlist</button>

    <div class="playlist-picker hidden">
      ${
        playlists.length
          ? playlists.map(p => `
              <button class="playlist-choice" data-name="${p.name}">
                ${p.name}
              </button>
            `).join("")
          : `<div style="color:#b3b3b3;padding:8px">No custom playlists yet</div>`
      }
    </div>
  `;

  document.body.appendChild(menu);

  const rect = button.getBoundingClientRect();
  menu.style.top = `${rect.bottom + 6}px`;
  menu.style.left = `${rect.left}px`;

  menu.querySelector(".downloadSongBtn")?.addEventListener("click", () => {
    downloadSong(song);
    closeSongMenu();
  });

  menu.querySelector(".addLibraryBtn")?.addEventListener("click", () => {
    addSongToLibrary(song);
    closeSongMenu();
  });

  menu.querySelector(".removeLibraryBtn")?.addEventListener("click", () => {
    removeSongFromLibrary(song);
    closeSongMenu();
  });

  const picker = menu.querySelector(".playlist-picker");

  menu.querySelector(".addToPlaylistBtn")?.addEventListener("click", (e) => {
    e.stopPropagation();
    picker?.classList.toggle("hidden");
  });

  menu.querySelectorAll(".playlist-choice").forEach(btn => {
    btn.addEventListener("click", () => {
      const playlist = state.customPlaylists.find(
        p => p.name === btn.dataset.name
      );

      if (!playlist) return;

      const exists = playlist.songs.some(
        s => String(s.id) === String(song.id)
      );

      if (!exists) {
        playlist.songs.push(song);
      }

      localStorage.setItem(
        "customPlaylists",
        JSON.stringify(state.customPlaylists)
      );

      renderLibrary();
      closeSongMenu();
    });
  });
}

function closeSongMenu() {
  document.querySelector(".song-menu")?.remove();
}

function downloadSong(song) {
  const a = document.createElement("a");

  a.href = `/api/songs/${song.id}/download`;
  a.download = `${song.title || "song"}.mp3`;

  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function addSongToLibrary(song) {
  await apiFetch("/api/library/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ songId: song.id })
  });

  await loadLibrary();
}

async function removeSongFromLibrary(song) {
  await apiFetch("/api/library/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ songId: song.id })
  });

  await loadLibrary();

  if (
    document.getElementById("homeView") &&
    !document.getElementById("homeView").classList.contains("hidden")
  ) {
    renderHome();
  }
}

function initProfileMenu() {

  const profileAvatar =
    document.getElementById("profileAvatar");

  const profileMenu =
    document.getElementById("profileMenu");

  const profileLogoutBtn =
    document.getElementById("profileLogoutBtn");

  const uploadProfilePicBtn =
    document.getElementById("uploadProfilePicBtn");

  const profilePicInput =
    document.getElementById("profilePicInput");

  const openStatsBtn =
    document.getElementById("openStatsBtn");

  if (!profileAvatar || !profileMenu) return;

  // ==========================
  // OPEN / CLOSE MENU
  // ==========================

  profileAvatar.addEventListener("click", (e) => {
    e.stopPropagation();
    profileMenu.classList.toggle("hidden");
  });

  profileMenu.addEventListener("click", (e) => {
    e.stopPropagation();
  });

  document.addEventListener("click", (e) => {

    if (
      e.target.closest("#profileAvatar") ||
      e.target.closest("#profileMenu")
    ) {
      return;
    }

    profileMenu.classList.add("hidden");
  });

  // ==========================
  // LOGOUT
  // ==========================

  profileLogoutBtn?.addEventListener("click", logout);

  // ==========================
  // OPEN PROFILE PIC PICKER
  // ==========================

  uploadProfilePicBtn?.addEventListener("click", () => {
    profilePicInput?.click();
  });

  // ==========================
  // PROFILE PIC UPLOAD
  // ==========================

  profilePicInput?.addEventListener("change", async (e) => {

    const file = e.target.files?.[0];

    if (!file) return;

    const formData = new FormData();

    formData.append("image", file);

    try {

      const res = await fetch(
        "/api/profile-picture",
        {
          method: "POST",
          body: formData
        }
      );

      const data = await res.json();

      const userBox = document.getElementById("userBox");

if (userBox && data.user) {
  userBox.innerText =
    `${data.user.firstName} ${data.user.lastName}`;
}

      if (!res.ok) {
        alert(data.error || "Upload failed");
        return;
      }

      if (data.profilePicture) {

        profileAvatar.innerHTML = "";

        profileAvatar.style.backgroundImage =
          `url('${data.profilePicture}')`;

        profileAvatar.style.backgroundSize =
          "cover";

        profileAvatar.style.backgroundPosition =
          "center";
      }

    } catch (err) {

      console.error(err);

      alert("Upload failed");
    }
  });

  // ==========================
  // STATS
  // ==========================

  openStatsBtn?.addEventListener("click", () => {

    profileMenu.classList.add("hidden");

    showView("stats");

    renderListeningStats();
  });
}

function initCustomPlaylists() {

  const btn =
    document.getElementById("createPlaylistBtn");

  if (!btn) return;

  btn.addEventListener("click", () => {

    const modal =
      document.getElementById("playlistModal");

    const input =
      document.getElementById("playlistNameInput");

    const saveBtn =
      document.getElementById("savePlaylistBtn");

    const cancelBtn =
      document.getElementById("cancelPlaylistBtn");

    if (!modal || !input) return;

    modal.classList.remove("hidden");

    input.value = "";
    input.focus();

    function closeModal() {
      modal.classList.add("hidden");
    }

    cancelBtn.onclick = closeModal;

    saveBtn.onclick = () => {

      const name = input.value.trim();

      if (!name) return;

      const exists = state.customPlaylists.some(
        p => p.name.toLowerCase() === name.toLowerCase()
      );

      if (exists) {
        alert("Playlist already exists");
        return;
      }

      const playlist = {
        name,
        songs: []
      };

      state.customPlaylists.push(playlist);

      localStorage.setItem(
        "customPlaylists",
        JSON.stringify(state.customPlaylists)
      );

      renderLibrary();

      closeModal();
    };
  });
}

function initMoreSheet() {
  const desktopMoreBtn = document.getElementById("desktopMoreBtn");
  const mobileMoreBtn = document.getElementById("mobileMoreBtn");
  const moreSheet = document.getElementById("moreSheet");
  const openQueueBtn = document.getElementById("openQueue");
  const openInfoBtn = document.getElementById("openInfo");
  const songInfoModal = document.getElementById("songInfoModal");
  const closeInfoBtn = document.getElementById("closeInfoBtn");
  const songInfoContent = document.getElementById("songInfoContent");

  openInfoBtn?.addEventListener("click", () => {
  const song = state.songs.find(
    s => String(s.id) === String(state.currentId)
  );

  if (!song) {
    songInfoContent.innerHTML =
      "<p style='color:#b3b3b3'>No song is currently playing.</p>";
  } else {
    songInfoContent.innerHTML = `
      <div class="song-info-row"><strong>Title:</strong> ${song.title || "Unknown"}</div>
      <div class="song-info-row"><strong>Artist:</strong> ${song.artist || "Unknown"}</div>
      <div class="song-info-row"><strong>Album:</strong> ${song.album || "Unknown"}</div>
      <div class="song-info-row"><strong>Release Year:</strong> ${song.year || "Unknown"}</div>
      <div class="song-info-row"><strong>Genre:</strong> ${song.genre || "Unknown"}</div>
    `;
  }

  moreSheet?.classList.add("hidden");
  songInfoModal?.classList.remove("hidden");
});

closeInfoBtn?.addEventListener("click", () => {
  songInfoModal?.classList.add("hidden");
});

songInfoModal?.addEventListener("click", (e) => {
  if (e.target === songInfoModal) {
    songInfoModal.classList.add("hidden");
  }
});

  function toggleMoreSheet(e) {
    e.stopPropagation();
    moreSheet?.classList.toggle("hidden");
  }

  desktopMoreBtn?.addEventListener("click", toggleMoreSheet);
  mobileMoreBtn?.addEventListener("click", toggleMoreSheet);

  moreSheet?.addEventListener("click", (e) => {
    e.stopPropagation();
  });

  document.addEventListener("click", (e) => {
    if (
      e.target.closest("#desktopMoreBtn") ||
      e.target.closest("#mobileMoreBtn") ||
      e.target.closest("#moreSheet")
    ) return;

    moreSheet?.classList.add("hidden");
  });

  openQueueBtn?.addEventListener("click", () => {
    showView("queue");
    renderQueue();
    moreSheet?.classList.add("hidden");
  });
}

async function loadLibrary() {
  const res = await apiFetch("/api/library");

  state.library = res?.songs || [];

  renderLibrary();
}

async function loadSavedPlaylists() {
  const res = await apiFetch("/api/playlists");

  if (!res?.playlists) return;

  const fullPlaylists = [];

  for (const p of res.playlists) {
    const details = await apiFetch(`/api/playlists/${p.id}`);

    if (details?.playlist && details?.songs) {
      fullPlaylists.push({
        id: details.playlist.id,
        name: details.playlist.name,
        type: details.playlist.is_generated ? "generated" : "playlist",
        songs: details.songs
      });
    }
  }

  state.libraryPlaylists = fullPlaylists;

  renderLibrary();
}
async function loadUser() {
  try {

    const res = await fetch("/api/me");

    const data = await res.json();

    const userBox =
      document.getElementById("userBox");

    if (userBox && data.user) {
      userBox.innerText =
        `${data.user.firstName} ${data.user.lastName}`;
    }

    const profileAvatar =
      document.getElementById("profileAvatar");

    if (
      profileAvatar &&
      data.user?.profilePicture
    ) {

      profileAvatar.innerHTML = "";

      profileAvatar.style.backgroundImage =
        `url('${data.user.profilePicture}')`;

      profileAvatar.style.backgroundSize =
        "cover";

      profileAvatar.style.backgroundPosition =
        "center";
    }

  } catch (err) {
    console.error(err);
  }
}

document.addEventListener("click", (e) => {

  if (
    !e.target.closest(".song-menu") &&
    !e.target.closest(".song-more-btn")
  ) {
    closeSongMenu();
  }
});

if (document.readyState === "loading") {

  document.addEventListener(
    "DOMContentLoaded",
    () => {

      initUI();
      initMoreSheet();
      initProfileMenu();
      initCustomPlaylists();

      loadUser();
      loadLibrary();
      loadSavedPlaylists();
    }
  );

} else {

  initUI();
  initMoreSheet();
  initProfileMenu();
  initCustomPlaylists();

  loadUser();
  loadLibrary();
  loadSavedPlaylists();
}
