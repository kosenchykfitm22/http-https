// Program.cs для InsecureHttpDemo
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Налаштовуємо лише HTTP-порт 8081 (за замовчуванням).
// У production ASP.NET Core це робиться через appsettings.json або Kestrel config, 
// але для демо використовуємо конфігурацію за замовчуванням.
// Для явного налаштування: 
// builder.WebHost.ConfigureKestrel(options => options.ListenAnyIP(8081));

// =========================================================
// 1. Головна сторінка з формою
// =========================================================
app.MapGet("/", () => Results.Content(
    """
    <html>
        <head><title>HTTP Insecure C#</title></head>
        <body>
            <h1>Увійдіть (Дані передаються відкритим текстом)</h1>
            <form method="post" action="/login">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Увійти">
            </form>
            <p style="color: red;">Цей трафік ЛЕГКО перехопити!</p>
        </body>
    </html>
    """, "text/html; charset=utf-8"));

// =========================================================
// 2. POST-ендпоінт для отримання даних форми
// =========================================================
app.MapPost("/login", ([FromForm] string username, [FromForm] string password) =>
{
    Console.WriteLine($"[HTTP] Login attempt received: User='{username}', Pass='{password}'");
    return Results.Ok();
})
.DisableAntiforgery();

app.Run();
