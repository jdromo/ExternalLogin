using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;
using AuthApi.Providers;
using AuthApi.Models;
using Microsoft.Owin.Security.Facebook;
using System.Threading.Tasks;

namespace AuthApi
{
  public partial class Startup
  {
    public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

    public static string PublicClientId { get; private set; }

    // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864
    public void ConfigureAuth(IAppBuilder app)
    {
      // Configure the db context and user manager to use a single instance per request
      app.CreatePerOwinContext(ApplicationDbContext.Create);
      app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);

      // Enable the application to use a cookie to store information for the signed in user
      // and to use a cookie to temporarily store information about a user logging in with a third party login provider
      app.UseCookieAuthentication(new CookieAuthenticationOptions());
      app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

      // Configure the application for OAuth based flow
      PublicClientId = "self";
      OAuthOptions = new OAuthAuthorizationServerOptions
      {
        TokenEndpointPath = new PathString("/Token"),
        Provider = new ApplicationOAuthProvider(PublicClientId),
        AuthorizeEndpointPath = new PathString("/api/Account/ExternalLogin"),
        AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
        // In production mode set AllowInsecureHttp = false
        AllowInsecureHttp = true
      };

      // Enable the application to use bearer tokens to authenticate users
      app.UseOAuthBearerTokens(OAuthOptions);

      // Uncomment the following lines to enable logging in with third party login providers
      //app.UseMicrosoftAccountAuthentication(
      //    clientId: "",
      //    clientSecret: "");

      //app.UseTwitterAuthentication(
      //    consumerKey: "",
      //    consumerSecret: "");

      //app.UseFacebookAuthentication(new FacebookAuthenticationOptions
      //{
      //  AppId = "1938146553135556",
      //  AppSecret = "cbefae8d049b27781ea4f0089e2de5b3",
      //  BackchannelHttpHandler = new FacebookBackChannelHandler(),
      //  // UserInformationEndpoint = "https://graph.facebook.com/v2.4/me?fields=id,name,email,first_name,last_name,location",
      //  UserInformationEndpoint = "https://graph.facebook.com/v2.4/me?fields=id,name,email",
      //  Scope = { "email" }
      //});

      var facebookOptions = new FacebookAuthenticationOptions()
      {
        AppId = "1938146553135556",
        AppSecret = "",
        BackchannelHttpHandler = new FacebookBackChannelHandler(),
        UserInformationEndpoint = "https://graph.facebook.com/v2.4/me?fields=id,name,email,first_name,last_name,location",
        Provider = new FacebookAuthenticationProvider
        {
          OnAuthenticated = context =>
          {
            context.Identity.AddClaim(new System.Security.Claims.Claim("FacebookAccessToken", context.AccessToken));
            return Task.FromResult(true);
          }
        }
      };
      facebookOptions.Scope.Add("email");
      facebookOptions.SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie;
      app.UseFacebookAuthentication(facebookOptions);

      //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
      //{
      //    ClientId = "",
      //    ClientSecret = ""
      //});
    }
  }
}
