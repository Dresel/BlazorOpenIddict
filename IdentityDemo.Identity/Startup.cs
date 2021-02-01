using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;

namespace IdentityDemo.Identity
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<IdentityContext>(options =>
            {
                options.UseSqlite("DataSource=identity.db");

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need
                // to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });

			services.AddAuthentication(options =>
            {
                options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            });

            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<IdentityContext>()
                .AddDefaultTokenProviders();

			// Configure Identity to use the same JWT claims as OpenIddict instead
			// of the legacy WS-Federation claims it uses by default (ClaimTypes),
			// which saves you from doing the mapping in your authorization controller.
			services.Configure<IdentityOptions>(options =>
			{
				options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
				options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
				options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
			});

            services.AddOpenIddict()

                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the Entity Framework Core stores and models.
                    // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                    options
                        .UseEntityFrameworkCore()
                        .UseDbContext<IdentityContext>();
                })

                // Register the OpenIddict server components.
                .AddServer(options =>
                {
                    options.DisableAccessTokenEncryption();

                    options.AddDevelopmentEncryptionCertificate()
                        .AddDevelopmentSigningCertificate();

                    // Enable the authorization, logout, token and userinfo endpoints.
                    options.SetAuthorizationEndpointUris("/connect/authorize")
                        .SetLogoutEndpointUris("/connect/logout")
                        .SetTokenEndpointUris("/connect/token")
                        .SetUserinfoEndpointUris("/connect/userinfo")
                        .SetIntrospectionEndpointUris("/connect/introspection");

                    // Mark the "email", "profile" and "roles" scopes as supported scopes.
                    options.RegisterScopes(OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Profile,
                            OpenIddictConstants.Scopes.Roles)
                        .RegisterScopes("api", "identity");

                    // Specify Authorization Code Flow and refresh token
                    options
                        .AllowAuthorizationCodeFlow()
                        .AllowRefreshTokenFlow();

                    // Register the ASP.NET Core host and configure the ASP.NET Core-specific Options.
                    options
                        .UseAspNetCore()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableLogoutEndpointPassthrough()
                        .EnableStatusCodePagesIntegration()
                        .EnableTokenEndpointPassthrough();
                });

            services.AddControllers();

            services.AddHostedService<DeleteAndCreateDatabaseHostedService>();
            services.AddHostedService<AddClientsHostedService>();
        }

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

			app.UseRouting();

            app.UseCors(builder =>
            {
                builder.WithOrigins("https://localhost:44325");
                builder.AllowAnyHeader();
                builder.AllowAnyMethod();
            });

            app.UseAuthentication();
            app.UseAuthorization();

			app.UseEndpoints(options =>
            {
                options.MapControllers();
                options.MapDefaultControllerRoute();
            });
		}
    }
}
