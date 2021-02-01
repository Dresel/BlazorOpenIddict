using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;

namespace IdentityDemo.Identity
{
	public class AddClientsHostedService : IHostedService
	{
		private readonly IServiceProvider serviceProvider;

		public AddClientsHostedService(IServiceProvider serviceProvider)
		{
			this.serviceProvider = serviceProvider;
		}

		public async Task StartAsync(CancellationToken cancellationToken)
		{
			using var scope = this.serviceProvider.CreateScope();



            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

			string clientId = "web";

			if (await manager.FindByClientIdAsync(clientId, cancellationToken) is null)
			{
				await manager.CreateAsync(
					new OpenIddictApplicationDescriptor
					{
						ClientId = clientId,
						DisplayName = "Blazor",
                        Type = OpenIddictConstants.ClientTypes.Public,
						PostLogoutRedirectUris =
                        {
                            new Uri("https://localhost:44325/authentication/logout-callback")
                        },
                        RedirectUris =
                        {
                            new Uri("https://localhost:44325/authentication/login-callback")
                        },
						Permissions =
						{
							OpenIddictConstants.Permissions.Endpoints.Authorization,
							OpenIddictConstants.Permissions.Endpoints.Token,
							OpenIddictConstants.Permissions.Endpoints.Logout,
							OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                            OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
							OpenIddictConstants.Permissions.ResponseTypes.Code,
                            OpenIddictConstants.Permissions.Scopes.Email,
                            OpenIddictConstants.Permissions.Scopes.Profile,
							OpenIddictConstants.Permissions.Scopes.Roles,
							OpenIddictConstants.Permissions.Prefixes.Scope + "api",
						},
                        Requirements =
                        {
                            OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                        }
					}, cancellationToken);
			}
        }

		public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
	}
}
