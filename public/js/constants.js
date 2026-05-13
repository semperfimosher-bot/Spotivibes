window.state = {
  songs: [],
  currentId: null,
  isPlaying: false,
  library: JSON.parse(localStorage.getItem("library")) || [],
};

window.audio = document.getElementById("audio");
