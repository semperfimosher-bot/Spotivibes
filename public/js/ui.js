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
    home: document.getElementById("homeView"),
    library: document.getElementById("libraryView"),
    queue: document.getElementById("queueView"),
    search: document.getElementById("searchView"),
  };

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

  if (!searchBar) return;

  searchBar.addEventListener(
    "input",
    debounce(handleLiveSearch, 120)
  );

  searchBar.addEventListener("keydown", (e) => {

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

  query = query.toLowerCase();
  text = text.toLowerCase();

  if (text === query) return 100;
  if (text.startsWith(query)) return 80;
  if (text.includes(query)) return 60;

  let score = 0;
  let qi = 0;

  for (let i = 0; i < text.length && qi < query.length; i++) {
    if (text[i] === query[qi]) {
      score += 10;
      qi++;
    }
  }

  return score;
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
async function handleLiveSearch(e) {
  const query = e.target.value.trim().toLowerCase();

  if (query.length < MIN_SEARCH_LENGTH) {
    closeSearchDropdown();
    return;
  }

  if (searchCache.has(query)) {
    renderSearchDropdown(searchCache.get(query));
    return;
  }

  const res = await apiFetch(`/api/search?q=${encodeURIComponent(query)}`);

  if (!res || !Array.isArray(res.songs)) {
    closeSearchDropdown();
    return;
  }

  const ranked = rankSongs(query, res.songs);
  searchCache.set(query, ranked);

  renderSearchDropdown(ranked);
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

  if (!res || !res.playlist) return;

  renderSearchResults(res.playlist);
}

// ==========================
// SEARCH RESULTS
// ==========================
function renderSearchResults(playlist) {
  const view = document.getElementById("searchView");
  const title = document.getElementById("searchTitle");
  const list = document.getElementById("searchList");

  if (!view || !title || !list) return;

  closeSearchDropdown();

  showView("search");

  title.textContent = playlist.name || "Search Results";
  list.innerHTML = "";

  const songs = playlist.songs || [];

  songs.forEach(song => {
    const row = createSongRow(song);
    list.appendChild(row);
  });
}

// ==========================
// COMPONENTS
// ==========================
function createSongCard(song) {
  const card = document.createElement("div");
  card.className = "card";
  card.dataset.id = song.id;

  card.innerHTML = `
    <div class="thumb"></div>
    <div>${song.title || "Unknown Title"}</div>
    <div style="color:#b3b3b3;font-size:12px">
      ${song.artist || "Unknown Artist"}
    </div>
  `;

  card.onclick = () => playSong(song.id);

  return card;
}

function createSongRow(song) {
  const row = document.createElement("div");
  row.className = "row";
  row.dataset.id = song.id;

  row.innerHTML = `
    <div>
      <div style="color:#fff">${song.title}</div>
      <div style="color:#b3b3b3;font-size:12px">${song.artist}</div>
    </div>
  `;

  row.onclick = () => playSong(song.id);

  return row;
}

// ==========================
// RENDER FUNCTIONS
// ==========================
function renderHome() {
  const recent = document.getElementById("recentGrid");
  const top = document.getElementById("topSongsGrid");

  if (!recent || !top) return;

  recent.innerHTML = "";
  top.innerHTML = "";

  const songs = state.songs || [];

  songs.slice(0, 8).forEach(s => recent.appendChild(createSongCard(s)));
  songs.slice(8, 16).forEach(s => top.appendChild(createSongCard(s)));

  highlightCurrentSong();
}

function renderLibrary() {
  const list = document.getElementById("libraryList");
  if (!list) return;

  list.innerHTML = "";

  const songs = state.library || [];

  if (!songs.length) {
    list.innerHTML = "<p style='color:#b3b3b3'>Your library is empty</p>";
    return;
  }

  songs.forEach(s => list.appendChild(createSongRow(s)));

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
  document.querySelectorAll(".row, .card").forEach(el => {
    el.style.outline = "none";
  });

  if (!state.currentId) return;

  document.querySelectorAll(".row, .card").forEach(el => {
    if (el.dataset?.id === state.currentId) {
      el.style.outline = "1px solid #0022ff";
    }
  });
}

// ==========================
// BOOTSTRAP
// ==========================
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initUI);
} else {
  initUI();
}

/* =========================
   MORE SHEET
========================= */

const moreBtn = document.getElementById("moreBtn");
const moreSheet = document.getElementById("moreSheet");

moreBtn?.addEventListener("click", () => {
  moreSheet?.classList.toggle("hidden");
});

/* =========================
   FULLSCREEN PLAYER
========================= */

const miniPlayer = document.getElementById("miniPlayer");
const fullscreenPlayer = document.getElementById("fullscreenPlayer");
const closeFullscreenBtn = document.getElementById("closeFullscreenPlayer");

miniPlayer?.addEventListener("click", (e) => {
  if (e.target.closest("button")) return;
  fullscreenPlayer?.classList.add("open");
});

closeFullscreenBtn?.addEventListener("click", () => {
  fullscreenPlayer?.classList.remove("open");
});