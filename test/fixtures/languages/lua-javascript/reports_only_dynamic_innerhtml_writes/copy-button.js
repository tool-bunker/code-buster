button.innerHTML = `<svg viewBox="0 0 24 24"></svg>`;
button.innerHTML = '<span>Copied</span>';
button.innerHTML =
  '<span>Saved</span>';
const previousMarkup = button.innerHTML;
const markupLength = button.innerHTML.length;
if (button.innerHTML === expectedMarkup) render();
// button.innerHTML = ignoredMarkup;
/*
button.innerHTML = ignoredMarkup;
*/
button.innerHTML = input;
button.innerHTML = `<span>${input}</span>`;
button.innerHTML += suffix;
button.innerHTML ||= fallbackMarkup;
button.innerHTML++;
--button.innerHTML;
button.innerHTML = null;
  document.body.innerHTML = '';
  document.body.innerHTML = userMarkup;
