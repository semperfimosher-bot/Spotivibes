window.addEventListener("DOMContentLoaded", async () => {
  await loadConfig();

  await loadUser();
  await loadSongs();
  await loadLibrary();
  await loadSavedPlaylists();
  await loadBackground();

  initUI();
  initMoreSheet();
  initProfileMenu();
  initCustomPlaylists();

  restoreLastPlayback?.();

  document.getElementById("playBtn")?.addEventListener("click", togglePlay);
  document.getElementById("nextBtn")?.addEventListener("click", nextSong);
  document.getElementById("prevBtn")?.addEventListener("click", prevSong);
});