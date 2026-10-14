/* Applies the saved (or system) theme before first paint, so the page never
   flashes light-then-dark. External file because the CSP forbids inline scripts. */
(function () {
  var theme = null;
  try {
    theme = localStorage.getItem("guardenv-theme");
  } catch (error) {
    theme = null;
  }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
  var meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", theme === "dark" ? "#0e1115" : "#e6e8eb");
})();
