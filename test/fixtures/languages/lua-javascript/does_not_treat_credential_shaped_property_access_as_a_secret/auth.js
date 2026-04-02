const url = `${identityUrl}/connect/token`;
payload["grant_type"] = "password";
payload["password"] = password;
payload["client_secret"] = clientSecret;
const password = "literal-secret";
