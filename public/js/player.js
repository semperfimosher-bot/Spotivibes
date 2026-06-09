let syncedLyrics = [];
let currentLyricIndex = -1;
let repeatMode = false;
let shuffleMode = false;

const LAST_PLAYBACK_KEY = "spotivibes_last_playback";

const playerAudioUrlCache = new Map();

let preloadAudio1 = new Audio();
let preloadAudio2 = new Audio();

preloadAudio1.preload = "auto";
preloadAudio2.preload = "auto";

const AUDIO_URL_CACHE_MS = 45 * 60 * 1000;

async function getCachedAudioUrl(songId) {
  const cached = playerAudioUrlCache.get(songId);

  if (cached && Date.now() < cached.expiresAt) {
    return cached.url;
  }

  const url = await getAudioUrl(songId);

  if (url) {
    playerAudioUrlCache.set(songId, {
      url,
      expiresAt: Date.now() + AUDIO_URL_CACHE_MS
    });
  }

  return url;
}
async function preloadNextTwoSongs() {
  const i = state.songs.findIndex(
    s => String(s.id) === String(state.currentId)
  );

  if (i === -1) return;

  const next1 = state.songs[i + 1];
  const next2 = state.songs[i + 2];

  if (next1) {
    const url1 = await getCachedAudioUrl(next1.id);
    if (url1) {
      preloadAudio1.src = url1;
      preloadAudio1.load();
    }
  }

  if (next2) {
    const url2 = await getCachedAudioUrl(next2.id);
    if (url2) {
      preloadAudio2.src = url2;
      preloadAudio2.load();
    }
  }
}

function getSong(id) {
  const songId = String(id);

  return (
    state.playbackContext?.songs
      ?.find(s => String(s.id) === songId) ||

    state.songs?.find(s => String(s.id) === songId) ||
    state.library?.find(s => String(s.id) === songId) ||
    state.libraryPlaylists
      ?.flatMap(p => p.songs || [])
      .find(s => String(s.id) === songId) ||
    state.customPlaylists
      ?.flatMap(p => p.songs || [])
      .find(s => String(s.id) === songId) ||
    null
  );
}

async function playSong(id) {
  const song = getSong(id);

  if (!song) {
    console.error("Song not found in player:", id);
    return;
  }

  state.currentId = song.id;
  state.isPlaying = true;

  trackListeningStats(song).catch(console.warn);

  let audioUrl;

if (!navigator.onLine && isSongDownloaded(song.id)) {
  audioUrl = getOfflineSongUrl(song.id);
} else if (isSongDownloaded(song.id)) {
  audioUrl = getOfflineSongUrl(song.id);
} else {
  audioUrl = await getCachedAudioUrl(song.id);
}

  if (!audioUrl) {
    console.error("No audio URL found for song:", song);
    return;
  }

  audio.src = audioUrl;
  audio.load();

  audio.onloadedmetadata = () => {
    audio.play().catch(console.warn);
  };

  const nowPlayingText = document.getElementById("nowPlayingText");
  if (nowPlayingText) {
    nowPlayingText.innerText = `${song.title} - ${song.artist}`;
  }

  const miniInfo = document.getElementById("miniInfo");
  if (miniInfo) {
    miniInfo.innerText = `${song.title} - ${song.artist}`;
  }

  const albumArt = document.getElementById("albumArt");
  if (albumArt) {
    albumArt.style.backgroundImage = song.coverUrl
      ? `url('${song.coverUrl}')`
      : "";
  }

  const miniAlbumArt = document.getElementById("miniAlbumArt");
  if (miniAlbumArt) {
    miniAlbumArt.style.backgroundImage = song.coverUrl
      ? `url('${song.coverUrl}')`
      : "";
  }

  loadSyncedLyrics(null);

getLyrics(song)
  .then(lyrics => {
    loadSyncedLyrics(lyrics);
  })
  .catch(err => {
    console.warn("Lyrics load failed:", err.message);
    loadSyncedLyrics(null);
  });

  updatePlayButton();
  highlightCurrentSong?.();
  preloadNextTwoSongs();

  apiFetch("/api/playback-event", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    songId: id,
    eventType: "play"
  })
}).catch(() => {});
}

async function togglePlay() {
  if (!audio.src) {
    if (state.currentId) playSong(state.currentId);
    return;
  }

  if (audio.paused) {
    audio.play();
    state.isPlaying = true;
  } else {
    audio.pause();
    state.isPlaying = false;
  }

  updatePlayButton();
}

function updatePlayButton() {
  const btn = document.getElementById("playBtn");
  if (btn) {
    btn.innerText = audio.paused ? "▶" : "⏸";
  }

  // 🔥 mobile sync
  const miniBtn = document.getElementById("miniPlayBtn");
  if (miniBtn) {
    miniBtn.innerText = audio.paused ? "▶" : "⏸";
  }
}

async function nextSong() {
  if (repeatMode && state.currentId) {
    audio.currentTime = 0;
    audio.play();
    return;
  }

  if (state.queue.length) {
    const next = state.queue.shift();
    await playSong(next.id);
    renderQueue?.();
    return;
  }

  const context = state.playbackContext;

  if (context?.songs?.length) {
    const nextIndex = context.index + 1;

    if (nextIndex < context.songs.length) {
      context.index = nextIndex;
      const nextSong = context.songs[nextIndex];

      await playSong(nextSong.id);
      return;
    }
  }

  try {
    const data = await apiFetch(
  `/api/recommendations/next?currentSongId=${state.currentId}`
);

    if (data?.songs?.length) {
      setPlaybackContext("recommendations", data.songs, 0);
      await playSong(data.songs[0].id);
      return;
    }
  } catch (err) {
    console.warn("Recommendation fallback failed:", err.message);
  }

  const i = state.songs.findIndex(
    s => String(s.id) === String(state.currentId)
  );

  const fallbackSong = state.songs[i + 1] || state.songs[0];

  if (fallbackSong) {
    setPlaybackContext("normal", state.songs, i + 1);
    await playSong(fallbackSong.id);
  }
}

async function prevSong() {
  const i = state.songs.findIndex(
    s => s.id === state.currentId
  );

  if (i > 0) {
    playSong(state.songs[i - 1].id);
  }
}

/* =========================
   MOBILE BUTTON WIRING
========================= */

document.getElementById("miniPlayBtn")
  ?.addEventListener("click", togglePlay);

document.getElementById("miniPrevBtn")
  ?.addEventListener("click", prevSong);

document.getElementById("miniNextBtn")
  ?.addEventListener("click", nextSong);

  document.getElementById("repeatBtn")
  ?.addEventListener("click", () => {
    repeatMode = !repeatMode;

    document
      .getElementById("repeatBtn")
      ?.classList.toggle("active", repeatMode);
  });

document.getElementById("shuffleBtn")
  ?.addEventListener("click", () => {
    shuffleMode = !shuffleMode;

    document
      .getElementById("shuffleBtn")
      ?.classList.toggle("active", shuffleMode);
  });

  document.getElementById("mobileShuffleBtn")
  ?.addEventListener("click", (e) => {
    e.stopPropagation();

    shuffleMode = !shuffleMode;

    document
      .querySelectorAll("#shuffleBtn, #mobileShuffleBtn")
      .forEach(btn => {
        btn.classList.toggle("active", shuffleMode);
      });

    console.log("Shuffle:", shuffleMode);
  });

document.getElementById("mobileRepeatBtn")
  ?.addEventListener("click", (e) => {
    e.stopPropagation();

    repeatMode = !repeatMode;

    document
      .querySelectorAll("#repeatBtn, #mobileRepeatBtn")
      .forEach(btn => {
        btn.classList.toggle("active", repeatMode);
      });

    console.log("Repeat:", repeatMode);
  });

/* =========================
   SMOOTH PROGRESS ENGINE
========================= */

let progressRAF = null;

function updateProgressBar() {

  const bar = document.getElementById("progressBar");
  const miniBar = document.getElementById("miniProgressBar");

  if (!audio.duration || isNaN(audio.duration)) {
    progressRAF = requestAnimationFrame(updateProgressBar);
    return;
  }

  updateSyncedLyrics();

  const progress =
    (audio.currentTime / audio.duration) * 100;

  const currentTimeEl =
    document.getElementById("currentTime");

  const durationEl =
    document.getElementById("duration");

  if (currentTimeEl) {
    currentTimeEl.innerText =
      formatTime(audio.currentTime);
  }

  if (durationEl) {
    durationEl.innerText =
      formatTime(audio.duration);
  }

  // desktop bar
  if (bar) {
    bar.value = progress;
  }

  // mobile bar
  if (miniBar) {
    miniBar.value = progress;
  }

  document.documentElement.style.setProperty(
    "--progress",
    `${progress}%`
  );

  localStorage.setItem(
  LAST_PLAYBACK_KEY,
  JSON.stringify({
    id: state.currentId,
    time: audio.currentTime
  })
);

  progressRAF =
    requestAnimationFrame(updateProgressBar);
}

audio.addEventListener("loadedmetadata", () => {
  cancelAnimationFrame(progressRAF);

  progressRAF =
    requestAnimationFrame(updateProgressBar);
});

audio.addEventListener("play", () => {
  cancelAnimationFrame(progressRAF);

  progressRAF =
    requestAnimationFrame(updateProgressBar);

  updatePlayButton();
});

audio.addEventListener("pause", () => {
  cancelAnimationFrame(progressRAF);

  updatePlayButton();
});

audio.addEventListener("ended", () => {
  cancelAnimationFrame(progressRAF);

  document.documentElement
    .style.setProperty("--progress", "0%");

  if (repeatMode) {
    audio.currentTime = 0;
    audio.play();
    return;
  }

  if (state.currentId) {
  apiFetch("/api/playback-event", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      songId: state.currentId,
      eventType: "complete"
    })
  }).catch(() => {});
}

if (state.currentId && audio.currentTime < audio.duration * 0.7) {
  apiFetch("/api/playback-event", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      songId: state.currentId,
      eventType: "skip"
    })
  }).catch(() => {});
}

  nextSong();
});

/* =========================
   SCRUBBING
========================= */

const progressBar =
  document.getElementById("progressBar");

const miniProgressBar =
  document.getElementById("miniProgressBar");

let isScrubbing = false;

function handleScrub(value) {
  if (!audio.duration) return;

  const newTime =
    (value / 100) * audio.duration;

  audio.currentTime = newTime;
}

/* desktop scrub */
progressBar?.addEventListener("input", (e) => {
  isScrubbing = true;
  handleScrub(Number(e.target.value));
});

progressBar?.addEventListener("change", (e) => {
  handleScrub(Number(e.target.value));
  isScrubbing = false;
});

/* mobile scrub */
miniProgressBar?.addEventListener("input", (e) => {
  isScrubbing = true;
  handleScrub(Number(e.target.value));
});

miniProgressBar?.addEventListener("change", (e) => {
  handleScrub(Number(e.target.value));
  isScrubbing = false;
});

/* =========================
   TOOLTIP
========================= */

const tooltip =
  document.getElementById("progressTooltip");

progressBar?.addEventListener("mousemove", (e) => {

  if (!audio.duration || !tooltip) return;

  const rect =
    progressBar.getBoundingClientRect();

  const percent =
    (e.clientX - rect.left) / rect.width;

  const time =
    percent * audio.duration;

  tooltip.innerText = formatTime(time);

  tooltip.style.left =
    `${e.clientX - rect.left}px`;

  tooltip.style.opacity = 1;
});

progressBar?.addEventListener("mouseleave", () => {
  if (tooltip) {
    tooltip.style.opacity = 0;
  }
});

function parseLRC(lyrics) {
  if (!lyrics) return [];

  const lines = [];

  lyrics.split("\n").forEach(line => {
    const timeMatches = [...line.matchAll(/\[(\d{1,2}):(\d{2})(?:\.(\d{1,3}))?\]/g)];
    const text = line
      .replace(/\[(\d{1,2}):(\d{2})(?:\.(\d{1,3}))?\]/g, "")
      .trim();

    if (!timeMatches.length || !text) return;

    timeMatches.forEach(match => {
      const minutes = Number(match[1]);
      const seconds = Number(match[2]);
      const ms = Number((match[3] || "0").padEnd(3, "0"));

      lines.push({
        time: minutes * 60 + seconds + ms / 1000,
        text
      });
    });
  });

  return lines.sort((a, b) => a.time - b.time);
}

function loadSyncedLyrics(lyrics) {
  const lyricsText = document.getElementById("lyricsText");

  if (!lyricsText) return;

  syncedLyrics = parseLRC(lyrics);
  currentLyricIndex = -1;

  if (!lyrics) {
    lyricsText.innerHTML = "No lyrics available";
    return;
  }

  if (!syncedLyrics.length) {
    lyricsText.innerText = lyrics;
    return;
  }

  lyricsText.innerHTML = syncedLyrics
  .map((line, index) =>
    `<div class="lyric-line" data-index="${index}">${line.text}</div>`
  )
  .join("");
}
function updateSyncedLyrics() {
  if (!syncedLyrics.length) return;

  const currentTime = audio.currentTime;

  let activeIndex = syncedLyrics.findIndex((line, index) => {
    const nextLine = syncedLyrics[index + 1];
    return currentTime >= line.time &&
      (!nextLine || currentTime < nextLine.time);
  });

  if (activeIndex === -1 || activeIndex === currentLyricIndex) return;

  currentLyricIndex = activeIndex;

  document.querySelectorAll(".lyric-line").forEach(line => {
    line.classList.remove("active");
  });

  const activeLine = document.querySelector(
    `.lyric-line[data-index="${activeIndex}"]`
  );

  if (activeLine) {
    activeLine.classList.add("active");

    activeLine.scrollIntoView({
      behavior: "smooth",
      block: "center"
    });
  }
}

/* =========================
   HELPERS
========================= */

function formatTime(seconds) {

  if (isNaN(seconds)) {
    return "0:00";
  }

  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);

  return `${m}:${s.toString().padStart(2, "0")}`;
}

async function restoreLastPlayback() {
  const saved = JSON.parse(
    localStorage.getItem(LAST_PLAYBACK_KEY) || "{}"
  );

  if (!saved.id) return;

  const song = getSong(saved.id);
  if (!song) return;

  state.currentId = song.id;

  highlightCurrentSong?.();

  // instant UI update
  document.getElementById("nowPlayingText").innerText =
    `${song.title} - ${song.artist}`;

  document.getElementById("miniInfo").innerText =
    `${song.title} - ${song.artist}`;

  const albumArt = document.getElementById("albumArt");
  if (albumArt) {
    albumArt.style.backgroundImage = song.coverUrl
      ? `url('${song.coverUrl}')`
      : "";
  }

  const miniAlbumArt = document.getElementById("miniAlbumArt");
  if (miniAlbumArt) {
    miniAlbumArt.style.backgroundImage = song.coverUrl
      ? `url('${song.coverUrl}')`
      : "";
  }

  loadSyncedLyrics(null);

getLyrics(song)
  .then(lyrics => {
    loadSyncedLyrics(lyrics);
  })
  .catch(err => {
    console.warn("Lyrics load failed:", err.message);
    loadSyncedLyrics(null);
  });

  updatePlayButton();

  // audio loads after UI
  const audioUrl = await getCachedAudioUrl(song.id);

if (!audioUrl) {
  console.error("No audio URL found for song:", song);
  return;
}

audio.src = audioUrl;
audio.load();

  audio.addEventListener("loadedmetadata", function restoreTime() {
    audio.removeEventListener("loadedmetadata", restoreTime);

    if (saved.time) {
      audio.currentTime = saved.time;
    }
  });
}

async function trackListeningStats(song) {
  if (!song?.id) return;

  await apiFetch("/api/listening-stats/play", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ songId: song.id })
  });
}

window.playSong = playSong;
window.nextSong = nextSong;
window.prevSong = prevSong;
window.togglePlay = togglePlay;
window.restoreLastPlayback = restoreLastPlayback;