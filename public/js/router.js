function initNavigation() {
  const bindNav = () => {
    document.querySelectorAll("[data-page]").forEach(btn => {
      if (btn.dataset.bound === "true") return;

      btn.dataset.bound = "true";

      btn.addEventListener("click", () => {
        const page = btn.dataset.page;

        if (page === "search") {
          showView("home");
          renderHome();

          setTimeout(() => {
            document.getElementById("searchBar")?.focus();
          }, 0);
        } else {
          showView(page);

          if (page === "home") {
            renderHome();
          }
        }

        updateActiveTab(page);
      });
    });
  };

  bindNav();

  setTimeout(bindNav, 300);

  document.getElementById("logoutBtn")?.addEventListener("click", logout);
}

/**
 * Updates active tab highlight for mobile nav and sidebar
 */
function updateActiveTab(page) {
  document
    .querySelectorAll("#mobileNav button[data-page], #sidebar-left button[data-page]")
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