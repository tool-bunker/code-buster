(function () {
  if (enabled) {
    start();
  }
  [1, 2, 3].forEach(function (value) {
    if (value === 1) return;
    if (value === 2) return;
    if (value === 3) return;
  });
  [1, 2, 3].forEach((value) => {
    if (value === 1) return;
    if (value === 2) return;
    if (value === 3) return;
  });
})();
