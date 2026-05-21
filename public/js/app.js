window.addEventListener("DOMContentLoaded", async () => {
  await loadConfig();

  initUI();
  initMoreSheet();
  initProfileMenu();
  initCustomPlaylists();

  await loadUser();
  await loadSongs();
  await loadLibrary();
  await loadSavedPlaylists();
  await loadBackground();

  restoreLastPlayback?.();

  document.getElementById("playBtn")?.addEventListener("click", togglePlay);
  document.getElementById("nextBtn")?.addEventListener("click", nextSong);
  document.getElementById("prevBtn")?.addEventListener("click", prevSong);

  window.addEventListener("scroll", async () => {
  const nearBottom =
    window.innerHeight + window.scrollY >= document.body.offsetHeight - 800;

  if (nearBottom) {
    await loadMoreSongs();
  }
});
});