// SecurityHeadersMiddleware.cs
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Впровадження захисних заголовків до того, як відповідь буде відправлена
        
        // HSTS: Примушує клієнта використовувати HTTPS
        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        
        // CSP: Захист від XSS
        context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'";
        
        // X-Frame-Options: Запобігає Clickjacking
        context.Response.Headers["X-Frame-Options"] = "DENY";
        
        // X-Content-Type-Options: Запобігає MIME-type sniffing
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        
        // Referrer-Policy
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        // Демонстрація захищеного cookie:
        // C# автоматично додасть "Secure" і "HttpOnly", якщо використовується HTTPS.
        context.Response.Cookies.Append(
            "SecureSession", 
            "UserTokenCS",
            new CookieOptions 
            {
                Secure = true, // Відправляти тільки через HTTPS
                HttpOnly = true, // Недоступний через JS (захист від XSS)
                SameSite = SameSiteMode.Strict // Захист від CSRF
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
