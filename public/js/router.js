function initNavigation() {
  const bindNav = () => {
    document.querySelectorAll("[data-page]").forEach(btn => {
      btn.onclick = () => {
        const page = btn.dataset.page;

        showView(page);
        updateActiveTab(page);
      };
    });
  };

  bindNav();

  // 🔧 in case mobile nav renders later
  setTimeout(bindNav, 300);

  document.getElementById("logoutBtn")?.addEventListener("click", logout);
}

/**
 * Updates active tab highlight for mobile nav
 */
function updateActiveTab(page) {
  document.querySelectorAll("#mobileNav button")
    .forEach(btn => {
      btn.classList.toggle(
        "active",
        btn.dataset.page === page
      );
    });
}

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
});