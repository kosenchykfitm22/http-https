
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {

        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        
        context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'";
        
        context.Response.Headers["X-Frame-Options"] = "DENY";
        
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        context.Response.Cookies.Append(
            "SecureSession", 
            "UserTokenCS",
            new CookieOptions 
            {
                Secure = true, 
                HttpOnly = true, 
                SameSite = SameSiteMode.Strict 
            }
        );

        await _next(context);
    }
}

public static class SecurityHeadersMiddlewareExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SecurityHeadersMiddleware>();
    }
}
