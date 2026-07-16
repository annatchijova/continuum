const toggle = document.getElementById("languageToggle");
let locale = "en";

function applyLocale() {
  document.documentElement.lang = locale;
  document.querySelectorAll("[data-en][data-es]").forEach((node) => {
    node.textContent = node.dataset[locale];
  });
  toggle.textContent = locale === "en" ? "ES" : "EN";
  toggle.setAttribute("aria-label", locale === "en" ? "Ver en español" : "View in English");
}

toggle.addEventListener("click", () => {
  locale = locale === "en" ? "es" : "en";
  applyLocale();
});
