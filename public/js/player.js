let syncedLyrics = [];
let currentLyricIndex = -1;
let repeatMode = false;
let shuffleMode = false;

const LAST_PLAYBACK_KEY = "spotivibes_last_playback";

function getSong(id) {
  return state.songs.find(s => String(s.id) === String(id));
}

function playSong(id) {
  const song = getSong(id);
  if (!song) return;

  state.currentId = id;

  trackListeningStats(song);

 const saved = JSON.parse(
  localStorage.getItem(LAST_PLAYBACK_KEY) || "{}"
);

audio.src = song.audioUrl;

audio.addEventListener("loadedmetadata", function restoreTime() {
  audio.removeEventListener("loadedmetadata", restoreTime);

  if (String(saved.id) === String(song.id) && saved.time) {
    audio.currentTime = saved.time;
  }

  audio.play();
});

  state.isPlaying = true;
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

  document.getElementById("nowPlayingText").innerText =
    `${song.title} - ${song.artist}`;

    loadSyncedLyrics(song.lyrics);

  const miniInfo = document.getElementById("miniInfo");
  if (miniInfo) {
    miniInfo.innerText = `${song.title} - ${song.artist}`;
  }

  // reset progress visual
  document.documentElement.style.setProperty("--progress", "0%");

  // glow effect
  document.getElementById("nowPlayingCard")
    ?.classList.add("playing");

  updatePlayButton();
  highlightCurrentSong?.();
}

function togglePlay() {
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

function nextSong() {
  if (repeatMode && state.currentId) {
  audio.currentTime = 0;
  audio.play();

  state.isPlaying = true;

  updatePlayButton();
  return;
}

  if (shuffleMode) {
    const otherSongs = state.songs.filter(
      s => String(s.id) !== String(state.currentId)
    );

    if (!otherSongs.length) return;

    const randomSong =
      otherSongs[Math.floor(Math.random() * otherSongs.length)];

    playSong(randomSong.id);
    return;
  }

  const i = state.songs.findIndex(
    s => String(s.id) === String(state.currentId)
  );

  if (i < state.songs.length - 1) {
    playSong(state.songs[i + 1].id);
  }
}

function prevSong() {
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

  return lyrics
    .split("\n")
    .map(line => {
      const match = line.match(/\[(\d+):(\d+\.\d+)\](.*)/);

      if (!match) return null;

      const minutes = Number(match[1]);
      const seconds = Number(match[2]);
      const text = match[3].trim();

      return {
        time: minutes * 60 + seconds,
        text
      };
    })
    .filter(item => item && item.text);
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

function restoreLastPlayback() {
  const saved = JSON.parse(
    localStorage.getItem(LAST_PLAYBACK_KEY) || "{}"
  );

  if (!saved.id) return;

  const song = getSong(saved.id);
  if (!song) return;

  state.currentId = song.id;

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

  loadSyncedLyrics?.(song.lyrics);
  updatePlayButton();

  // audio loads after UI
  audio.src = song.audioUrl;

  audio.addEventListener("loadedmetadata", function restoreTime() {
    audio.removeEventListener("loadedmetadata", restoreTime);

    if (saved.time) {
      audio.currentTime = saved.time;
    }
  });
}

function trackListeningStats(song) {

if (!song || !song.title || !song.artist) return;

  const stats =
    JSON.parse(localStorage.getItem("listeningStats")) || {};

  const artist = song.artist || "Unknown Artist";
  const title = song.title || "Unknown Title";

  if (!stats[artist]) {
    stats[artist] = {};
  }

  if (!stats[artist][title]) {
    stats[artist][title] = 0;
  }

  stats[artist][title] += 1;

  localStorage.setItem(
    "listeningStats",
    JSON.stringify(stats)
  );
}
