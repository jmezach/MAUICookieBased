using System.Net;
using Android.Webkit;
using MAUICookieBasedTest.Services;

namespace MAUICookieBasedTest;

public partial class WebViewPage : ContentPage
{
	public WebViewPage(AccountStore accountStore)
	{
        InitializeComponent();

        var uri = new Uri("https://ad3b-45-144-217-92.eu.ngrok.io", UriKind.RelativeOrAbsolute);
        var cookieContainer = new CookieContainer();
        //cookieContainer.SetCookies(uri, accountStore.CurrentAccount.CookieHeader);
        cookieContainer.Add(new Cookie("abuse_interstitial", uri.Host, "/", uri.Host) { HttpOnly = true, Secure = true });

        webView.Cookies = cookieContainer;
        webView.Source = new UrlWebViewSource() { Url = uri.ToString() };
    }

    void webView_Navigated(System.Object sender, Microsoft.Maui.Controls.WebNavigatedEventArgs e)
    {
#if ANDROID
        if (CookieManager.Instance.HasCookies)
        {

        }
#endif
    }

    void webView_Navigating(System.Object sender, Microsoft.Maui.Controls.WebNavigatingEventArgs e)
    {
    }
}
