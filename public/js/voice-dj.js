let voiceRecognition = null;
let voiceListening = false;
let waitingForCommand = false;

function speakSpoti(text) {
  try {
    const msg = new SpeechSynthesisUtterance(text);
    msg.rate = 1;
    msg.pitch = 1;
    speechSynthesis.speak(msg);
  } catch {}
}

async function runVoiceCommand(command) {
  const cleanCommand = String(command || "").trim();

  const cmd = cleanCommand.toLowerCase();

if (cmd.includes("shut off") || cmd.includes("turn off") || cmd.includes("stop listening")) {
  stopVoiceDj();
  return;
}

if (cmd.includes("pause") || cmd.includes("stop music")) {
  audio.pause();
  state.isPlaying = false;
  updatePlayButton();
  speakSpoti("Paused.");
  return;
}

if (cmd.includes("resume") || cmd.includes("keep playing")) {
  audio.play();
  state.isPlaying = true;
  updatePlayButton();
  speakSpoti("Playing.");
  return;
}

if (cmd.includes("skip") || cmd.includes("next song")) {
  speakSpoti("Skipping.");
  nextSong();
  return;
}

if (cmd.includes("start over") || cmd.includes("restart song")) {
  audio.currentTime = 0;
  speakSpoti("Starting over.");
  return;
}

if (cmd.includes("louder") || cmd.includes("volume up")) {
  audio.volume = Math.min(1, audio.volume + 0.15);
  speakSpoti("Volume up.");
  return;
}

if (cmd.includes("quieter") || cmd.includes("volume down")) {
  audio.volume = Math.max(0, audio.volume - 0.15);
  speakSpoti("Volume down.");
  return;
}

if (cmd.includes("mute")) {
  audio.muted = true;
  speakSpoti("Muted.");
  return;
}

if (cmd.includes("unmute")) {
  audio.muted = false;
  speakSpoti("Unmuted.");
  return;
}

  if (!cleanCommand) return;

  console.log("VOICE COMMAND:", cleanCommand);

  try {
    const data = await apiFetch("/api/ai-dj-command", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        command: cleanCommand,
        currentSongId: state.currentId
      })
    });

    if (!data?.success) {
      speakSpoti(data?.message || "I could not do that.");
      return;
    }

    if (data.action === "pause") {
      audio.pause();
      state.isPlaying = false;
      updatePlayButton();
      speakSpoti("Paused.");
      return;
    }

    if (data.action === "resume") {
      audio.play();
      state.isPlaying = true;
      updatePlayButton();
      speakSpoti("Playing.");
      return;
    }

    if (data.action === "skip") {
      speakSpoti("Skipping.");
      nextSong();
      return;
    }

    if (data.action === "continueMood") {
      speakSpoti("Continuing the vibe.");
      nextSong();
      return;
    }

    if (data.action === "playSongs" && data.songs?.length) {
      setPlaybackContext(data.contextType || "ai-dj", data.songs, 0);
      await playSong(data.songs[0].id);
      speakSpoti(data.message || "Playing now.");
      return;
    }

    speakSpoti(data.message || "Done.");

  } catch (err) {
    console.warn("Voice command failed:", err.message);
    speakSpoti("Something went wrong.");
  }
}

function startVoiceDj() {
  const SpeechRecognition =
    window.SpeechRecognition || window.webkitSpeechRecognition;

  if (!SpeechRecognition) {
    alert("Voice recognition is not supported in this browser. Try Chrome on Android or desktop.");
    return;
  }

  if (voiceListening) return;

  voiceRecognition = new SpeechRecognition();
  voiceRecognition.continuous = true;
  voiceRecognition.interimResults = false;
  voiceRecognition.lang = "en-US";

  voiceRecognition.onresult = async (event) => {
  const last = event.results[event.results.length - 1];
  const transcript = last[0].transcript.toLowerCase().trim();

  console.log("HEARD:", transcript);

  const wakeWords = [
    "hey spoti",
    "hey spotty",
    "hey spotify",
    "hey spatai",
    "spoti",
    "spotty",
    "spotify",
    "spatai"
  ];

  const matchedWakeWord = wakeWords.find(word =>
    transcript.includes(word)
  );

  if (matchedWakeWord) {
    const command = transcript
      .replace(matchedWakeWord, "")
      .trim();

    if (
      command === "shut off" ||
      command === "turn off" ||
      command === "stop listening"
    ) {
      stopVoiceDj();
      return;
    }

    if (command) {
      waitingForCommand = false;
      await runVoiceCommand(command);
    } else {
      waitingForCommand = true;
      speakSpoti("Listening.");
    }

    return;
  }

  if (waitingForCommand) {
    waitingForCommand = false;
    await runVoiceCommand(transcript);
  }
};

  voiceRecognition.onerror = (err) => {
    console.warn("Voice recognition error:", err.error);
  };

  voiceRecognition.onend = () => {
    if (voiceListening) {
      try {
        voiceRecognition.start();
      } catch {}
    }
  };

  voiceListening = true;
  document.getElementById("voiceDjBtn")?.classList.add("listening");

  voiceRecognition.start();
  speakSpoti("Hey Spoti is on.");
}

function stopVoiceDj() {
  voiceListening = false;
  waitingForCommand = false;

  document.getElementById("voiceDjBtn")?.classList.remove("listening");

  try {
    voiceRecognition?.stop();
  } catch {}

  speakSpoti("Hey Spoti is off.");
}

document.getElementById("voiceDjBtn")?.addEventListener("click", () => {
  if (voiceListening) {
    stopVoiceDj();
  } else {
    startVoiceDj();
  }
});