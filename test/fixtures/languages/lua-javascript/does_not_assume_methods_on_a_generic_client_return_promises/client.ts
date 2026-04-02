client.load().subscribe(handleValue);
const login = () =>
  client.login();
client.postMessage(message);
client.mockReset();
client.unhandled();
client.start();
client.requestSnapshot();
client.stop();
