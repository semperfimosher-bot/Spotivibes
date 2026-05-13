window.addEventListener("DOMContentLoaded", async () => {
  await loadUser();
  await loadSongs();
  await loadBackground();

  initUI();

  document.getElementById("playBtn")?.addEventListener("click", togglePlay);
  document.getElementById("nextBtn").onclick = nextSong;
  document.getElementById("prevBtn").onclick = prevSong;
});
