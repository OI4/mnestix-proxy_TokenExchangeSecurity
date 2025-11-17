using Microsoft.AspNetCore.Authorization;
using mnestix_proxy.Authentication;
using mnestix_proxy.Authentication.ApiKeyAuthentication;
using mnestix_proxy.Authentication.ApiKeyAuthorization;
using mnestix_proxy.Authentication.TokenExchange;
using mnestix_proxy.Configuration;
using mnestix_proxy.Middleware;
using mnestix_proxy.Services.Clients;

namespace mnestix_proxy
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            
            _ = bool.TryParse(builder.Configuration["TokenExchange:EnableTokenExchange"],
                out var exchangeToken);

            if (exchangeToken)
            {
                builder.Services.AddReverseProxy()
                    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
                    .AddTransforms<FxTransformProvider>();

                builder.Services.Configure<FxTransformProvider.SecureTokenExchangeService>(
                    builder.Configuration.GetSection("TokenExchange:SecureTokenExchangeService"));

            }
            else
            {
                builder.Services.AddReverseProxy()
                    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
            }
            
            //Discovery Client settings
            builder.Services.AddTransient<IDiscoveryClient, DiscoveryClient>();
            builder.Services.Configure<DiscoveryServiceOptions>(
                builder.Configuration.GetSection(DiscoveryServiceOptions.Options));

            builder.Services.AddAuthenticationServices(builder.Configuration);

            // Add HTTP client to establish Token Exchange via Secure Token Service (STS) for authorization in Factory-X context
            builder.Services.AddHttpClient();

            // Adds authorization handler
            builder.Services.AddScoped<IAuthorizationHandler, ApiKeyRequirementHandler>();

            builder.Services.Configure<CustomerEndpointsSecurityOptions>(
                builder.Configuration.GetSection(CustomerEndpointsSecurityOptions.CustomerEndpointsSecurity));

            builder.Services.AddAuthorizationBuilder()
                .AddPolicy("customApiKeyToModifyValuesPolicy", policyBuilder => policyBuilder
                    .AddRequirements(new ApiKeyRequirement()));

            // in some classes we need the base url of the request
            builder.Services.AddHttpContextAccessor();

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("allowAnything", corsPolicyOptions =>
                {
                    corsPolicyOptions.AllowAnyOrigin();
                    corsPolicyOptions.AllowAnyHeader();
                    corsPolicyOptions.AllowAnyMethod();
                });
            });

            // pipeline settings
            var app = builder.Build();

            app.UseMnestixConfiguredAuth(builder.Configuration);

            app.UseCors("allowAnything");

            app.MapReverseProxy(proxyPipeline =>
            {
                // Path Restricting
                _ = bool.TryParse(builder.Configuration["Features:AllowRetrievingAllShellsAndSubmodels"],
                       out var allowRetrievingAllShellsAndSubmodels);
                if (!allowRetrievingAllShellsAndSubmodels)
                {
                    proxyPipeline.Use(PathRestrictionMiddleware.PathRestrictionHandling());
                }

                // AAS registry
                _ = bool.TryParse(builder.Configuration["Features:AasDiscoveryMiddleware"],
                    out var aasRegistryMiddleware);
                if (aasRegistryMiddleware)
                {
                    proxyPipeline.Use(AasDiscoveryServiceMiddleware.ConfigureAasDiscoveryHandling());
                }

                // MQTT Eventing
                _ = bool.TryParse(builder.Configuration["MQTTEventing:mqtt_events_enabled"],
                    out var mqttEventingEnabled);
                if (mqttEventingEnabled)
                {
                    var logger = LoggerFactory.Create(builder => builder.AddConsole())
                        .CreateLogger<MqttEventingMiddleware>();
                    var mqttEventingMiddleware =
                        new MqttEventingMiddleware(builder.Configuration.GetSection("MQTTEventing"), logger);
                    proxyPipeline.Use(mqttEventingMiddleware.ConfigureMqttEventingHandling());
                }

            });

            app.Run();
        }
    }
}