const registerForm = document.getElementById("loginForm");

registerForm?.addEventListener("submit", async (e) => {
  e.preventDefault();

  await loadConfig();

  const firstName = document.getElementById("firstName").value.trim();
  const lastName = document.getElementById("lastName").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  try {
    const data = await apiFetch("/api/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        firstName,
        lastName,
        email,
        password
      })
    });

    if (data?.success) {
      window.location.href = "/app";
    } else {
      alert(data?.error || "Register failed");
    }

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    alert(err.message || "Register failed");
  }
});