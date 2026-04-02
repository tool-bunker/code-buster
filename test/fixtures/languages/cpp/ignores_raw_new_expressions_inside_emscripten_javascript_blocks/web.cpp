Native *first = new Native();
EM_JS(int, readFile, (), {
  const reader = new FileReader();
  reader.onload = () => { window.file = reader.result; };
});
EM_ASM({
  new Notification("Ready", { body: "Complete" });
});
Native *last = new Native();
