// ==========================
// SEARCH INTELLIGENCE LAYER
// ==========================
let searchCache = new Map();
let activeDropdownIndex = -1;
let currentDropdownItems = [];
let suppressSearchDropdown = false;

function setPlaybackContext(type, songs = [], index = 0) {
  state.playbackContext = {
    type,
    songs,
    index
  };
}

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
  debounce((e) => {
    suppressSearchDropdown = false;
    handleSearch(e);
  }, 120)
);

 searchBar?.addEventListener("keydown", async (e) => {

if (e.key === "Enter") {
  e.preventDefault();

  const query = searchBar.value.trim();

  if (!query) return;
  suppressSearchDropdown = true;

  closeSearchDropdown();

  const dropdown =
    document.getElementById("searchDropdown");

  if (dropdown) {
    dropdown.innerHTML = "";
    dropdown.classList.add("hidden");
    dropdown.style.display = "none";
  }

  searchBar.blur();

  apiFetch(`/api/smart-search?q=${encodeURIComponent(query)}`)
    .then(renderSmartSearchResults)
    .catch(err => {
      console.warn("Search failed:", err.message);
    });

  return;
}
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
  const seenPlaylists = new Set();

  res.playlists.forEach(playlist => {
    const key = playlist.name.toLowerCase();

    if (seenPlaylists.has(key)) return;

    seenPlaylists.add(key);

    results.appendChild(
      createGeneratedPlaylistCard(playlist)
    );
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

  setPlaybackContext("suggestions", [song], 0);

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
  const query = e.target.value.trim();

  if (suppressSearchDropdown) {
  closeSearchDropdown();
  return;
}

  if (!query) {
    closeSearchDropdown();
    return;
  }

  saveRecentSearch(query);

  const localSongs = rankSongs(query, state.songs || [])
    .filter(s => s.score > 0)
    .slice(0, 8);

  renderSearchDropdown(localSongs);

  apiFetch(`/api/smart-search?q=${encodeURIComponent(query)}`)
    .then(res => {
      renderSearchDropdown(res.songs || []);
    })
    .catch(err => {
      console.warn("Search suggestions failed:", err.message);
    });
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
  data.songs.forEach((song, index) => {
    list.appendChild(
      createSongRow(song, {
        onClick: () => {
          setPlaybackContext("search", data.songs, index);
          playSong(song.id);
        }
      })
    );
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

  playlist.songs.forEach((song, index) => {
    list.appendChild(
      createSongRow(song, {
        onClick: () => {
          setPlaybackContext("playlist", playlist.songs, index);
          playSong(song.id);
        }
      })
    );
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
        ${playlist.type || "playlist"} · ${playlist.songs.length} songs
      </div>
    </div>

    <button class="playlist-add-btn">
      Add
    </button>
  `;

  row.addEventListener("click", () => {
    renderPlaylistSongs(playlist);
  });

  const addBtn = row.querySelector(".playlist-add-btn");

addBtn?.addEventListener("click", (e) => {
  e.stopPropagation();

  const tempPlaylist = {
    id: `temp-${Date.now()}`,
    name: playlist.name,
    type: playlist.type || "generated",
    songs: playlist.songs || []
  };

  const previousPlaylists = [...state.libraryPlaylists];

  state.libraryPlaylists = [tempPlaylist, ...state.libraryPlaylists];
  renderLibrary();

  addBtn.innerText = "Added";

  apiFetch("/api/playlists/save", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      name: playlist.name,
      query: playlist.name,
      songs: playlist.songs
    })
  })
    .then(async () => {
      await loadSavedPlaylists();
    })
    .catch(err => {
      console.warn("Save playlist failed:", err.message);
      state.libraryPlaylists = previousPlaylists;
      renderLibrary();
      addBtn.innerText = "Add";
      alert("Could not save playlist.");
    });
});

  return row;
}
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
  ?.addEventListener("click", async (e) => {
    e.stopPropagation();

    const res = await apiFetch("/api/playlists/remove", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ playlistId: playlist.id })
    });

    if (!res?.success) {
      alert("Failed to remove playlist from database");
      return;
    }

    await loadSavedPlaylists();
    renderLibrary();

    menu.classList.add("hidden");
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

function getSongCover(song) {
  return song.coverUrl || song.cover_url || song.image || song.artwork || "";
}

function sameId(a, b) {
  return String(a) === String(b);
}

function hasSong(list, songId) {
  return list.some(s => sameId(s.id, songId));
}

function upsertSong(list, song) {
  if (hasSong(list, song.id)) return list;
  return [song, ...list];
}

function removeSongById(list, songId) {
  return list.filter(s => !sameId(s.id, songId));
}

function createSongCard(song) {
  const card = document.createElement("div");
  card.className = "card";
  card.dataset.id = song.id;

  card.innerHTML = `

    <div 
     class="thumb" 
     style="background-image:url('${getSongCover(song)}')"
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

   card.addEventListener("click", () => window.playSong(song.id));

  const moreBtn = card.querySelector(".song-more-btn");

  moreBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    openSongMenu(song, moreBtn);
  });

  return card;
}

function createSongRow(song, options = {}) {

  const row = document.createElement("div");

  row.className = "row";

  row.dataset.id = song.id;

  row.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;flex:1">

      <div
        class="row-thumb"
        style="background-image:url('${getSongCover(song)}')"
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

  // ==========================
  // SWIPE TO QUEUE
  // ==========================

  let startX = 0;
  let currentX = 0;

  const swipeLabel = document.createElement("div");

  swipeLabel.className = "swipe-queue-label";

  swipeLabel.innerText = "Add to queue";

  row.prepend(swipeLabel);

  row.addEventListener("touchstart", (e) => {

    startX = e.touches[0].clientX;

    currentX = startX;
  });

  row.addEventListener("touchmove", (e) => {

    currentX = e.touches[0].clientX;

    const diff = currentX - startX;

    if (diff > 0 && diff < 140) {
      row.style.transform =
        `translateX(${diff}px)`;
    }

    if (diff > 80) {
      swipeLabel.classList.add("active");
    } else {
      swipeLabel.classList.remove("active");
    }
  });

  row.addEventListener("touchend", () => {

    const diff = currentX - startX;

    if (diff > 115) {

  addToQueue(song);

  showQueueToast(song);

  row.style.transform =
    "translateX(120px)";

      setTimeout(() => {
        row.style.transform = "";
      }, 150);
    } else {

      row.style.transform = "";
    }

    swipeLabel.classList.remove("active");
  });

  // ==========================
  // PLAY SONG
  // ==========================

  row.addEventListener("click", () => {
  if (options.onClick) {
    options.onClick();
    return;
  }

  setPlaybackContext("suggestions", [song], 0);
  playSong(song.id);
});

  // ==========================
  // MORE BUTTON
  // ==========================

  const moreBtn =
    row.querySelector(".song-more-btn");

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
      style="background-image:url('${getSongCover(song)}')"
    ></div>

    <div class="compact-info">
      <div>${song.title || "Unknown Title"}</div>
      <div>${song.artist || "Unknown Artist"}</div>
    </div>
  `;

  row.addEventListener("click", () => window.playSong(song.id));

  return row;
}

function createSidebarLibraryRow(song) {
  const row = document.createElement("div");
  row.className = "sidebar-library-row";
  row.dataset.id = song.id;

  row.innerHTML = `
    <div
      class="sidebar-library-thumb"
      style="background-image:url('${getSongCover(song)}')"
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

async function renderListeningStats() {
  const list = document.getElementById("artistStatsList");
  if (!list) return;

  const data = await apiFetch("/api/listening-stats");
  const stats = data?.stats || {};

  list.innerHTML = "";

  const artists = Object.keys(stats);

  if (!artists.length) {
    list.innerHTML = "<p style='color:#b3b3b3'>No listening stats yet.</p>";
    return;
  }

  artists
    .sort((a, b) => {
      const totalA = Object.values(stats[a]).reduce((sum, count) => sum + count, 0);
      const totalB = Object.values(stats[b]).reduce((sum, count) => sum + count, 0);
      return totalB - totalA;
    })
    .forEach(artist => {
      const totalPlays = Object.values(stats[artist]).reduce((sum, count) => sum + count, 0);

      const row = document.createElement("div");
      row.className = "row";

      row.innerHTML = `
        <div>
          <div style="color:white">${artist}</div>
          <div style="color:#b3b3b3;font-size:12px">${totalPlays} total plays</div>
        </div>
      `;

      row.addEventListener("click", () => renderArtistSongStats(artist, stats));
      list.appendChild(row);
    });
}

function renderArtistSongStats(artist, stats) {
  const list = document.getElementById("artistStatsList");
  if (!list) return;

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

  document.getElementById("backToArtistsBtn")?.addEventListener("click", renderListeningStats);
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

  songs.slice(0, 100).forEach(s => recent.appendChild(createSongCard(s)));
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

  playlists.forEach(p => {
    list.appendChild(createSidebarPlaylistRow(p));

    if (sidebarList) {
      sidebarList.appendChild(createSidebarPlaylistRow(p));
    }
  });

  songs.slice(0, 100).forEach(s => {
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

  if (!state.queue.length) {
    list.innerHTML = "<p style='color:#b3b3b3'>Queue is empty</p>";
    return;
  }

  state.queue.forEach(song => {
    list.appendChild(createSongRow(song));
  });
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
    btn.addEventListener("click", async () => {
      const playlist = state.customPlaylists.find(
        p => p.name === btn.dataset.name
      );

      if (!playlist) return;

      const exists = playlist.songs.some(
        s => String(s.id) === String(song.id)
      );

     const previousSongs = [...playlist.songs];

if (!playlist.songs.some(s => String(s.id) === String(song.id))) {
  playlist.songs.unshift(song);
}

renderLibrary();
closeSongMenu();

apiFetch("/api/playlists/add-song", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    playlistName: playlist.name,
    songId: song.id
  })
}).catch(err => {
  console.warn("Add to playlist failed:", err.message);
  playlist.songs = previousSongs;
  renderLibrary();
  alert("Could not add song to playlist.");
});

await loadSavedPlaylists();
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

function showQueueToast(song) {

  const toast = document.createElement("div");

  toast.className = "queue-toast";

  toast.innerText =
    `${song.title} added to queue`;

  document.body.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("show");
  }, 10);

  setTimeout(() => {

    toast.classList.remove("show");

    setTimeout(() => {
      toast.remove();
    }, 200);

  }, 1800);
}

async function addSongToLibrary(song) {
  const previousLibrary = [...state.library];

  state.library = upsertSong(state.library, song);
  renderLibrary();

  apiFetch("/api/library/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ songId: song.id })
  }).catch(err => {
    console.warn("Add to library failed:", err.message);
    state.library = previousLibrary;
    renderLibrary();
    alert("Could not add song to library.");
  });
}

async function removeSongFromLibrary(song) {
  const previousLibrary = [...state.library];

  state.library = removeSongById(state.library, song.id);
  renderLibrary();

  apiFetch("/api/library/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ songId: song.id })
  }).catch(err => {
    console.warn("Remove from library failed:", err.message);
    state.library = previousLibrary;
    renderLibrary();
    alert("Could not remove song from library.");
  });
}

function addToQueue(song) {
  const exists = state.queue.some(
    s => String(s.id) === String(song.id)
  );

  if (!exists) {
    state.queue.push(song);
    renderQueue();
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
    const data = await apiFetch("/api/profile-picture", {
      method: "POST",
      body: formData
    });

    if (data.profilePicUrl) {
  document.querySelectorAll("#profileAvatar, #userAvatar, .profile-avatar")
    .forEach(avatar => {
      if (avatar.tagName === "IMG") {
        avatar.src = data.profilePicUrl;
      } else {
        avatar.style.backgroundImage = `url('${data.profilePicUrl}')`;
      }
    });
}

    if (!data) {
      alert("Upload failed");
      return;
    }

    if (data.profilePicture) {
      profileAvatar.innerHTML = "";
      profileAvatar.style.backgroundImage = `url('${data.profilePicture}')`;
      profileAvatar.style.backgroundSize = "cover";
      profileAvatar.style.backgroundPosition = "center";
    }

    const userBox = document.getElementById("userBox");

    if (userBox && data.user) {
      userBox.innerText =
        `${data.user.firstName} ${data.user.lastName}`;
    }

  } catch (err) {
    console.error(err);
    alert("Upload failed");
  }
});

  // ==========================
  // STATS
  // ==========================

 openStatsBtn?.addEventListener("click", async () => {
  profileMenu.classList.add("hidden");
  showView("stats");
  await renderListeningStats();
});

}

function initCustomPlaylists() {

  const buttons = [
  document.getElementById("createPlaylistBtn"),
  document.getElementById("mobileCreatePlaylistBtn")
].filter(Boolean);

 if (!buttons.length) return;

buttons.forEach(btn => {
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

    saveBtn.onclick = async () => {

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

     await apiFetch("/api/playlists/custom", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name })
});

await loadSavedPlaylists();
renderLibrary();

      renderLibrary();

      closeModal();
    };
  });
});
}

function initMoreSheet() {
  const desktopMoreBtn = document.getElementById("desktopMoreBtn");
  const mobileMoreBtn = document.getElementById("mobileMoreBtn");
  const moreSheet = document.getElementById("moreSheet");
  const openQueueBtn = document.getElementById("openQueue");
  const openInfoBtn = document.getElementById("openInfo");
  const songInfoModal = document.getElementById("songInfoModal");
  const closeInfoBtn = document.getElementById("closeSongInfo");
  const songInfoContent = document.getElementById("songInfoContent");
  const openVoiceDjBtn = document.getElementById("openVoiceDj");

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

openQueueBtn?.addEventListener("click", () => {
  showView("queue");
  renderQueue();
  moreSheet?.classList.add("hidden");
});

openVoiceDjBtn?.addEventListener("click", () => {
  if (window.voiceListening) {
    window.stopVoiceDj?.();
  } else {
    window.startVoiceDj?.();
  }

  moreSheet?.classList.add("hidden");
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
}

async function loadLibrary() {
  const res = await apiFetch("/api/library");

  if (!res?.songs) {
    console.warn("Library reload failed. Keeping current library.");
    return;
  }

  state.library = res.songs;
  renderLibrary();
}

async function loadSavedPlaylists() {
  const res = await apiFetch("/api/playlists");

  if (!res?.playlists) {
    console.warn("Playlist reload failed. Keeping current playlists.");
    return;
  }

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
    } else {
      console.warn("Failed to load playlist details:", p.id);
    }
  }

  state.libraryPlaylists = fullPlaylists;
  state.customPlaylists = fullPlaylists.filter(
    p => p.type !== "generated"
  );

  renderLibrary();
}

async function loadUser() {
  try {
    const data = await apiFetch("/api/me");

    const userBox = document.getElementById("userBox");

    if (userBox && data.user) {
      userBox.innerText =
        `${data.user.firstName} ${data.user.lastName}`;
    }

    const profileAvatar =
      document.getElementById("profileAvatar");

    if (profileAvatar && data.user?.profilePicUrl) {
      profileAvatar.innerHTML = "";

      profileAvatar.style.backgroundImage =
        `url('${data.user.profilePicUrl}')`;

      profileAvatar.style.backgroundSize = "cover";
      profileAvatar.style.backgroundPosition = "center";
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
