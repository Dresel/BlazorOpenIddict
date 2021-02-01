using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IdentityDemo.Identity
{
    public class DeleteAndCreateDatabaseHostedService : IHostedService
    {
        private readonly IServiceProvider serviceProvider;

        public DeleteAndCreateDatabaseHostedService(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = this.serviceProvider.CreateScope();

            IdentityContext context = scope.ServiceProvider.GetRequiredService<IdentityContext>();

            await context.Database.EnsureDeletedAsync(cancellationToken);
            await context.Database.EnsureCreatedAsync(cancellationToken);
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
