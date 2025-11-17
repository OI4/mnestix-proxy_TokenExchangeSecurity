using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;
using Microsoft.Extensions.Options;

namespace mnestix_proxy.Authentication.TokenExchange;

internal sealed class FxTransformProvider : ITransformProvider
{
    public void ValidateRoute(TransformRouteValidationContext context)
    {
    }

    public void ValidateCluster(TransformClusterValidationContext context)
    {
    }

    public void Apply(TransformBuilderContext transformBuilderContext)
    {
        transformBuilderContext.RequestTransforms.Add(new RequestFuncTransform(async context =>
        {
            var httpClient = context.HttpContext.RequestServices.GetRequiredService<HttpClient>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<FxTransformProvider>>();

            // Try to get typed config from DI (recommended), otherwise attempt to bind manually
            var config = context.HttpContext.RequestServices
                .GetService<IOptions<SecureTokenExchangeService>>()?.Value;
                

            if (config == null)
            {
                logger.LogWarning("SecureTokenExchangeService section missing or malformed. Skipping token exchange.");
                return; // skip transform when config is not available
            }

            // Send initial request to get first JWT token
            var request = new HttpRequestMessage(HttpMethod.Post, config.CredentialTokenUrl);
            request.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", config.CredentialClientId),
                new KeyValuePair<string, string>("client_secret", config.CredentialClientSecret)
            });

            var response = await httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

            logger.LogInformation("Got JWT from token credential.aas-voyager.com: {Token}", tokenResponse!.AccessToken);

            // Send second request to token exchange service
            request = new HttpRequestMessage(HttpMethod.Post, config.TokenExchangeUrl);
            request.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
                new KeyValuePair<string, string>("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                new KeyValuePair<string, string>("subject_token", tokenResponse!.AccessToken)
            });

            response = await httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

            logger.LogInformation("Got JWT from token exchange: {Token}", tokenResponse!.AccessToken);

            // Attach token from STS to the proxy request
            context.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
        }));
    }

    private sealed record TokenResponse([property:JsonPropertyName("access_token")] string AccessToken);
    public sealed class SecureTokenExchangeService
    {
        public SecureTokenExchangeService() { }

        public string CredentialTokenUrl { get; init; } = null!;
        public string CredentialClientId { get; init; } = null!;
        public string CredentialClientSecret { get; init; } = null!;
        public string TokenExchangeUrl { get; init; } = null!;
    }
}