axios.Axios = Axios;
axios.default = axios;
axios.request = axios.request.bind(axios);
client.load.bind(client);
api.addComponents = api.addComponents.bind(api);
axios("/pending");
axios.get("/pending");
client.load();
