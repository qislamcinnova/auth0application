
namespace Auth0Application.Handlers;

public static class CustomAuthEventHandler
{
    public static Task OnAccessDenied(Microsoft.AspNetCore.Authentication.AccessDeniedContext context, string generalAccessDeniedPath, string accountVerificationPath)
    {
        if (context.HttpContext.Request.HasFormContentType)
        {
            context.AccessDeniedPath = accountVerificationPath;
            return Task.CompletedTask;
        }

        context.AccessDeniedPath = generalAccessDeniedPath;
        return Task.CompletedTask;
    }
}

