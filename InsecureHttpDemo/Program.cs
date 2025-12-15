
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

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


app.MapPost("/login", ([FromForm] string username, [FromForm] string password) =>
{
    Console.WriteLine($"[HTTP] Login attempt received: User='{username}', Pass='{password}'");
    return Results.Ok();
})
.DisableAntiforgery();

app.Run();
