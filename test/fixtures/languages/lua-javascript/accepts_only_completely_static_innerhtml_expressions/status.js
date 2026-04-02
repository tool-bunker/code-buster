panel.innerHTML =
  '<div class="status">' +
  '<span>Ready</span>' +
  '</div>';
arrow.innerHTML = collapsed ? '&#x25BC;' : '&#x25B6;';
message.innerHTML =
  '<pre>' +
  payload.replace(/</g, '&lt;') +
  '</pre>';
message.innerHTML = ok ? '<p>Ready</p>' : renderError();
