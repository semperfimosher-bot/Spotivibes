function getSong(id) {
  return state.songs.find(s => s.id === id);
}

function playSong(id) {
  const song = getSong(id);
  if (!song) return;

  state.currentId = id;

  audio.src = song.audioUrl;
  audio.currentTime = 0;
  audio.play();

  state.isPlaying = true;

  document.getElementById("nowPlayingText").innerText =
    `${song.title} - ${song.artist}`;

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
  const i = state.songs.findIndex(
    s => s.id === state.currentId
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

  document.getElementById("nowPlayingCard")
    ?.classList.remove("playing");
});

audio.addEventListener("ended", () => {
  cancelAnimationFrame(progressRAF);

  document.documentElement
    .style.setProperty("--progress", "0%");

  document.getElementById("nowPlayingCard")
    ?.classList.remove("playing");

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
