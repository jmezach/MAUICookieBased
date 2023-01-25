using System;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

namespace MAUICookieBasedTest.Services;

public class AccountStore
{
    private readonly ILogger<AccountStore> _logger;
    private readonly HttpClient _httpClient;
    private Account _account = null;

    public AccountStore(ILogger<AccountStore> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://ad3b-45-144-217-92.eu.ngrok.io")
        };
    }

    public Account CurrentAccount { get => _account; }

    public async Task<Account> MigrateAccountAsync()
    {
        try
        {
            // Check if account has been migrated in the old app
            var wasMigrated = await LegacySecureStorage.GetAsync("XamarinAuthAccountStoreMigratedDeVriesAppService");
            if (wasMigrated == "1")
            {
                // Migrated, so read the data
                _logger.LogInformation("Accounts were migrated and are accessible");
                var json = await LegacySecureStorage.GetAsync("DeVriesAppService");
                var accounts = JsonNode.Parse(json).AsArray();
                var account = accounts.FirstOrDefault();
                if (account != null)
                {
                    var response = await _httpClient.PostAsJsonAsync("/account/migrate", account);
                    if (response.IsSuccessStatusCode && response.Headers.TryGetValues("Set-Cookie", out var cookies))
                    {
                        _account = new Account
                        {
                            CookieHeader = cookies.FirstOrDefault()
                        };

                        return _account;
                    }

                    /*
					var handler = new JsonWebTokenHandler();
					var idToken = handler.ReadJsonWebToken(account["Properties"]["id_token"].GetValue<string>());

					return new Account
					{
						Username = idToken.GetClaim(JwtRegisteredClaimNames.Name).Value,
						AccessToken = account["Properties"]["access_token"].GetValue<string>()
					};
					*/
                }

                return null;
            }
            else
            {
                // Not migrated
                _logger.LogInformation("Accounts weren't migrated or not available");
                // TODO: This isn't going to work, people need to migrate to a newer jobapp version first
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occured while accessing accounts.");
            return null;
        }
    }

    public class Account
    {
        public string Username { get; init; }

        public string AccessToken { get; init; }

        public string CookieHeader { get; set; }
    }
}

