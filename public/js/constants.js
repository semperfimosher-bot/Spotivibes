window.state = {
  songs: [],
  queue: [],
  currentId: null,
  isPlaying: false,
  library: [],
  libraryPlaylists: [],
  customPlaylists: [],

  playbackContext: {
    type: "normal",
    songs: [],
    index: 0
  }
};

window.audio = document.getElementById("audio");