// Loaded in <head> so the saved theme is applied before first paint (no flash).
(() => {
  try {
    const t = localStorage.getItem('sb_theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch { /* storage blocked: follow the OS */ }
})();
