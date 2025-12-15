
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(8443, listenOptions =>
    {
        listenOptions.UseHttps(); 
    });
});

var app = builder.Build();

app.UseSecurityHeaders(); 

app.MapGet("/", () => Results.Content(
    """
    <html>
        <head><title>HTTPS Secure C#</title></head>
        <body>
            <h1>Увійдіть (Трафік захищено TLS)</h1>
            <form method="post" action="/login">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Увійти">
            </form>
            <p style="color: green;">Трафік зашинфрований. Сніфер побачить лише криптограму.</p>
        </body>
    </html>
    """, "text/html; charset=utf-8"));

app.MapPost("/login", ([FromForm] string username, [FromForm] string password) =>
{
    Console.WriteLine($"[HTTPS] Login attempt received for user: {username}");
    return Results.Ok();
})
.DisableAntiforgery();

app.Run();
