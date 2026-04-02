const wchar_t* script = L"\
function replaceImage(image) {\n\
  if (image) { return true; }\n\
}\n\
";
int NativeFunction() {
  return 1;
}
