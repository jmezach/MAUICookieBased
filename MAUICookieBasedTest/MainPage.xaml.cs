using MAUICookieBasedTest.Services;

namespace MAUICookieBasedTest;

public partial class MainPage : ContentPage
{
	private readonly AccountStore _accountStore;

	public MainPage(AccountStore accountStore)
	{
		_accountStore = accountStore ?? throw new ArgumentNullException(nameof(accountStore));

		InitializeComponent();
	}

	private async void OnMigrateClicked(object sender, EventArgs e)
	{
		var account = await _accountStore.MigrateAccountAsync();
		if (account == null)
		{
			MigrateBtn.Text = "Migration failed";
		}

		await Navigation.PushAsync(new WebViewPage(_accountStore));
	}
}


