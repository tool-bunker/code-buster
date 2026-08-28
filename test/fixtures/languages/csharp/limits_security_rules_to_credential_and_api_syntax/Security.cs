class Security {
  void Validate() {
    Debug.Assert(user is not null);
    var message = $"Cannot delete secret '{name}' because it is active.";
    var passwordKey = "Database:Password";
    // RC2 is accepted only by a legacy provider.
    public const string ManageResetPassword = "manageresetpassword";
    public const string PasswordHash = "password_hash_b64";
    public const string FeaturePassword = "pm-27086-input-password";
    public const string IdentityCertPassword = "IDENTITY_CERT_PASSWORD";
    var accessToken = "";
    var oauthToken = "   ";
    var testPassword = "test";
    var authToken = "liveTokenValue123";
    var requestToken = "https://api.example.com/oauth/request";
    var continuationToken = "1234567890";
    var fakeApiKey = "fake-key";
    var appClientSecret = "testAppClientSecret";
    var clsToken = "[CLS]";
    var unknownToken = "<UNKNOWN>";
    var maxToken = "gen_ai.request.max_tokens";
    var versionToken = "Version=";
    var assignToken = "=";
    var headerNameAzureApiKey = "api-key";
    const string PSSnapinToken = "pssnapin";
    static readonly string AliasDescriptionToken = "Description";
    const string FunctionValueToken = "ScriptBlock";
    const string Token = " {0}='{1}'";
    const string QuotasToken = "<Quotas {0} />";
    const string TokenLabel = "Jellyfin-Token";
    const string ApiKey = "195003";
    const string IsApiKey = "Jellyfin-IsApiKey";
    const string DefaultPassword = "asdfasdfasdf";
    var password = "literal-secret";
    var sqlQuery = $"SELECT * FROM Users WHERE Id = {id}";
    string queryString = "Select * From Win32_Service Where ProcessId=" + process.Id;
    cimSession.QueryInstances("root/cimv2", "WQL", queryString);
    public string MD5 { get; set; } = "";
    if (entity.MD5 == md5) return;
    var passwordDigest = MD5.Create();
    PermissionSet permissions = LoadPermissions();
  }
}
