window.addEventListener("DOMContentLoaded", async () => {
  await loadUser();
  await loadSongs();
  await loadBackground();

  initUI();

  restoreLastPlayback?.();

  document.getElementById("playBtn")?.addEventListener("click", togglePlay);
  document.getElementById("nextBtn").addEventListener("click", nextSong);
  document.getElementById("prevBtn").addEventListener("click", prevSong);
});
