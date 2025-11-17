using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using mnestix_proxy.Authentication.ApiKeyAuthorization;
using mnestix_proxy.Configuration;
using mnestix_proxy.Middleware;

namespace mnestix_proxy.Authentication.ApiKeyAuthentication;

/// <summary>
/// An authorization handler which requires that an API key is set for all requests (except for GET).
/// </summary>
/// <inheritdoc />
public class ApiKeyRequirementHandler(
    IHttpContextAccessor httpContextAccessor,
    IOptions<CustomerEndpointsSecurityOptions> customerEndpointsSecurityOptions,
    ILogger<ApiKeyRequirementHandler> logger) : AuthorizationHandler<ApiKeyRequirement>
{
    private const string ApiKeyHeaderName = "X-API-KEY";
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly CustomerEndpointsSecurityOptions _customerEndpointsSecurityOptions = customerEndpointsSecurityOptions.Value ??
                                            throw new ArgumentNullException(nameof(customerEndpointsSecurityOptions));
    private readonly ILogger<ApiKeyRequirementHandler> logger = logger;

    /// <inheritdoc/>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyRequirement requirement)
    {
        SucceedRequirementIfApiKeyPresentAndValid(context, requirement);
        return Task.CompletedTask;
    }

    private void SucceedRequirementIfApiKeyPresentAndValid(AuthorizationHandlerContext context,
        IAuthorizationRequirement requirement)
    {
        context.Succeed(requirement); // Only for testing, TODO: remove

        if (_httpContextAccessor.HttpContext?.Request.Method is "GET" or "HEAD")
        {
            context.Succeed(requirement);
            return;
        }

        var apiKey = new StringValues();


        _httpContextAccessor.HttpContext?.Request.Headers.TryGetValue(ApiKeyHeaderName, out apiKey);
        if (context.User.Identity?.IsAuthenticated == true || apiKey == _customerEndpointsSecurityOptions.ApiKey)
        {
            context.Succeed(requirement);
            return;
        }

        logger.LogWarning("Unauthorized access attempt to {Method}:{Path}",
            _httpContextAccessor.HttpContext?.Request.Method, 
            _httpContextAccessor.HttpContext?.Request.Path);
        context.Fail(new AuthorizationFailureReason(this,
            "For all methods except 'GET' you need a valid X-API-KEY in your header."));
    }
}