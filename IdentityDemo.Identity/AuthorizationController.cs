namespace IdentityDemo.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.IdentityModel.Tokens;
    using OpenIddict.Abstractions;
    using OpenIddict.Server.AspNetCore;

    public class AuthorizationController : ControllerBase
    {
		private readonly IOpenIddictApplicationManager applicationManager;
		private readonly SignInManager<IdentityUser> signInManager;
		private readonly UserManager<IdentityUser> userManager;

		public AuthorizationController(IOpenIddictApplicationManager applicationManager, SignInManager<IdentityUser> signInManager,
			UserManager<IdentityUser> userManager)
		{
			this.applicationManager = applicationManager;
			this.signInManager = signInManager;
			this.userManager = userManager;
		}

		[HttpGet("~/connect/authorize")]
		[HttpPost("~/connect/authorize")]
		[IgnoreAntiforgeryToken]
		public async Task<IActionResult> Authorize()
		{
			OpenIddictRequest? request = HttpContext.GetOpenIddictServerRequest() ??
				throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

			// Retrieve the user principal stored in the authentication cookie.
			var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

			// If the user principal can't be extracted, redirect the user to the login page.
			if (result?.Succeeded != true)
			{
				return Challenge(authenticationSchemes: IdentityConstants.ApplicationScheme,
					properties: new AuthenticationProperties
					{
						RedirectUri = Request.PathBase + Request.Path +
							QueryString.Create(Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList()),
					});
			}

			// Retrieve the profile of the logged in user.
			var user = await this.userManager.GetUserAsync(User) ??
				throw new InvalidOperationException("The user details cannot be retrieved.");

			// Create a new ClaimsPrincipal containing the claims that
			// will be used to create an id_token, a token or a code.
			var principal = await this.signInManager.CreateUserPrincipalAsync(user);

			// Set requested scopes (this is not done automatically)
			principal.SetScopes(request.GetScopes());

			foreach (var claim in principal.Claims)
			{
				claim.SetDestinations(GetDestinations(claim, principal));
			}

			// Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
			return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		[HttpPost("~/connect/token")]
		public async Task<IActionResult> Exchange()
		{
			OpenIddictRequest? request = HttpContext.GetOpenIddictServerRequest() ??
				throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

			return request switch
			{
				{ } when request.IsClientCredentialsGrantType() => await HandleClientCredentialsGrantType(request),
				{ } when request.IsAuthorizationCodeGrantType() => await HandleAuthorizationCodeGrantType(),
				_ => throw new InvalidOperationException("The specified grant type is not supported."),
			};
		}

		[HttpGet("~/connect/logout")]
		public async Task<IActionResult> Logout()
		{
			// Ask ASP.NET Core Identity to delete the local and external cookies created
			// when the user agent is redirected from the external identity provider
			// after a successful authentication flow (e.g Google or Facebook).
			await this.signInManager.SignOutAsync();

			// Returning a SignOutResult will ask OpenIddict to redirect the user agent
			// to the post_logout_redirect_uri specified by the client application.
			return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
		{
			// Note: by default, claims are NOT automatically included in the access and identity tokens.
			// To allow OpenIddict to serialize them, you must attach them a destination, that specifies
			// whether they should be included in access tokens, in identity tokens or in both.
			switch (claim.Type)
			{
				case OpenIddictConstants.Claims.Name:
					yield return OpenIddictConstants.Destinations.AccessToken;

					if (principal.HasScope(OpenIddictConstants.Scopes.Profile))
					{
						yield return OpenIddictConstants.Destinations.IdentityToken;
					}

					yield break;

				case OpenIddictConstants.Claims.Email:
					yield return OpenIddictConstants.Destinations.AccessToken;

					if (principal.HasScope(OpenIddictConstants.Scopes.Email))
					{
						yield return OpenIddictConstants.Destinations.IdentityToken;
					}

					yield break;

				case OpenIddictConstants.Claims.Role:
					yield return OpenIddictConstants.Destinations.AccessToken;

					if (principal.HasScope(OpenIddictConstants.Scopes.Roles))
					{
						yield return OpenIddictConstants.Destinations.IdentityToken;
					}

					yield break;

				// Never include the security stamp in the access and identity tokens, as it's a secret value.
				case "AspNet.Identity.SecurityStamp":
					yield break;

				default:
					yield return OpenIddictConstants.Destinations.AccessToken;

					yield break;
			}
		}

		private async Task<IActionResult> HandleAuthorizationCodeGrantType()
		{
			// Retrieve the claims principal stored in the authorization code
			ClaimsPrincipal principal =
				(await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal ??
				throw new InvalidOperationException();

			var user = await this.userManager.GetUserAsync(principal) ??
				throw new InvalidOperationException("The user details cannot be retrieved.");

			// Ensure the user is still allowed to sign in.
			if (!await this.signInManager.CanSignInAsync(user))
			{
				return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
					properties: new AuthenticationProperties(new Dictionary<string, string?>
					{
						[OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
						[OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in.",
					}));
			}

			foreach (var claim in principal.Claims)
			{
				claim.SetDestinations(GetDestinations(claim, principal));
			}

			// Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
			return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		private async Task<IActionResult> HandleClientCredentialsGrantType(OpenIddictRequest request)
		{
			object? application = await this.applicationManager.FindByClientIdAsync(request.ClientId!);

			if (application == null)
			{
				throw new InvalidOperationException("The application details cannot be found in the database.");
			}

			// Create a new ClaimsIdentity containing the claims that
			// will be used to create an id_token, a token or a code.
			var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, OpenIddictConstants.Claims.Name,
				OpenIddictConstants.Claims.Role);

			// Use the client_id as the subject identifier.
			identity.AddClaim(OpenIddictConstants.Claims.Subject, await this.applicationManager.GetClientIdAsync(application),
				OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);

			identity.AddClaim(OpenIddictConstants.Claims.Name, await this.applicationManager.GetDisplayNameAsync(application),
				OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);

			ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);
			claimsPrincipal.SetScopes(request.GetScopes());

			return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

	}
}
