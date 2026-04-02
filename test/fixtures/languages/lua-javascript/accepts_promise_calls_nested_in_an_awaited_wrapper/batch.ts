const responses = await Promise.all([
  fetch("/one"),
  fetch("/two"),
]);
fetch("/unhandled");
