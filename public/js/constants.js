window.state = {
  songs: [],
  currentId: null,
  isPlaying: false,
  library: JSON.parse(localStorage.getItem("library")) || [],
  libraryPlaylists: JSON.parse(localStorage.getItem("libraryPlaylists")) || [],
  customPlaylists: JSON.parse(localStorage.getItem("customPlaylists")) || [],
};

window.audio = document.getElementById("audio");
