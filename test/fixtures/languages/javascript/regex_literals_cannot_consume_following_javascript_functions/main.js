function stripFences(content) {
  return content.replace(/^(`{3,})[^\n]*\n[\s\S]*?^\1\s*$/gm, '');
}

function following(value) {
  if (value) return true;
  return false;
}
