using BookNookAPI;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
});

builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
{
    options.SerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true
    };
});
builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "BookNook API", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type=ReferenceType.SecurityScheme, Id="Bearer" }
            },
            new string[]{}
        }
    });
});

var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication(); 
app.UseAuthorization();

//AUTH ENDPOINT

app.MapPost("/api/login", (UserLogin user, IConfiguration config) =>
{
    if (user.Username == "admin" && user.Password == "password123")
    {
        var issuer = config["Jwt:Issuer"];
        var audience = config["Jwt:Audience"];
        var key = Encoding.ASCII.GetBytes(config["Jwt:Key"]!);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("Id", Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                new Claim(JwtRegisteredClaimNames.Email, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti,
                Guid.NewGuid().ToString())
             }),
            Expires = DateTime.UtcNow.AddMinutes(5), // Token lives 5 minutes
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);
        return Results.Ok(new { token = jwtToken });
    }
    return Results.Unauthorized();
});

//AUTHORS

app.MapGet("/api/authors", async (ApplicationDbContext db) =>
    await db.Authors.Include(a => a.Books).ToListAsync());

app.MapGet("/api/authors/{id}", async (ApplicationDbContext db, int id) =>
{
    var author = await db.Authors.Include(a => a.Books).FirstOrDefaultAsync(a => a.Id == id);
    return author is null ? Results.NotFound() : Results.Ok(author);
});

app.MapPost("/api/authors", async (ApplicationDbContext db, [FromBody] Author newAuthor) =>
{
    db.Authors.Add(newAuthor);
    await db.SaveChangesAsync();
    return Results.Created($"/api/authors/{newAuthor.Id}", newAuthor);
}).RequireAuthorization(); // Secured

app.MapPut("/api/authors/{id}", async (ApplicationDbContext db, int id, [FromBody] Author updatedAuthor) =>
{
    var author = await db.Authors.FindAsync(id);
    if (author is null) return Results.NotFound();
    author.Name = updatedAuthor.Name;
    await db.SaveChangesAsync();
    return Results.Ok(author);
}).RequireAuthorization(); // Secured

app.MapDelete("/api/authors/{id}", async (ApplicationDbContext db, int id) =>
{
    var author = await db.Authors.FindAsync(id);
    if (author is null) return Results.NotFound();
    db.Authors.Remove(author);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization(); // Secured

app.MapGet("/api/authors/{authorId}/books", async (ApplicationDbContext db, int authorId) =>
{
    if (!await db.Authors.AnyAsync(a => a.Id == authorId)) return Results.NotFound("Author not found.");
    return Results.Ok(await db.Books.Where(b => b.AuthorId == authorId).ToListAsync());
});

//BOOKS 

app.MapGet("/api/books", async (ApplicationDbContext db) =>
    await db.Books.Include(b => b.Author).Include(b => b.Reviews).ToListAsync());

app.MapGet("/api/books/{id}", async (ApplicationDbContext db, int id) =>
{
    var book = await db.Books.Include(b => b.Author).Include(b => b.Reviews).FirstOrDefaultAsync(b => b.Id == id);
    return book is null ? Results.NotFound() : Results.Ok(book);
});

app.MapPost("/api/books", async (ApplicationDbContext db, [FromBody] Book newBook) =>
{
    if (!await db.Authors.AnyAsync(a => a.Id == newBook.AuthorId)) return Results.BadRequest("Invalid AuthorId.");
    db.Books.Add(newBook);
    await db.SaveChangesAsync();
    return Results.Created($"/api/books/{newBook.Id}", newBook);
}).RequireAuthorization(); // Secured

app.MapPut("/api/books/{id}", async (ApplicationDbContext db, int id, [FromBody] Book updatedBook) =>
{
    var book = await db.Books.FindAsync(id);
    if (book is null) return Results.NotFound();
    if (!await db.Authors.AnyAsync(a => a.Id == updatedBook.AuthorId)) return Results.BadRequest("Invalid AuthorId.");
    book.Title = updatedBook.Title;
    book.Genre = updatedBook.Genre;
    book.Description = updatedBook.Description;
    book.AuthorId = updatedBook.AuthorId;
    await db.SaveChangesAsync();
    return Results.Ok(book);
}).RequireAuthorization(); // Secured

app.MapDelete("/api/books/{id}", async (ApplicationDbContext db, int id) =>
{
    var book = await db.Books.FindAsync(id);
    if (book is null) return Results.NotFound();
    db.Books.Remove(book);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization(); // Secured

app.MapGet("/api/books/{bookId}/reviews", async (ApplicationDbContext db, int bookId) =>
{
    if (!await db.Books.AnyAsync(b => b.Id == bookId)) return Results.NotFound("Book not found.");
    return Results.Ok(await db.Reviews.Where(r => r.BookId == bookId).ToListAsync());
});

//REVIEWS 

app.MapGet("/api/reviews", async (ApplicationDbContext db) =>
    await db.Reviews.Include(r => r.Book).ToListAsync());

app.MapGet("/api/reviews/{id}", async (ApplicationDbContext db, int id) =>
{
    var review = await db.Reviews.Include(r => r.Book).FirstOrDefaultAsync(r => r.Id == id);
    return review is null ? Results.NotFound() : Results.Ok(review);
});

app.MapPost("/api/reviews", async (ApplicationDbContext db, [FromBody] Review newReview) =>
{
    if (!await db.Books.AnyAsync(b => b.Id == newReview.BookId)) return Results.BadRequest("Invalid BookId.");
    db.Reviews.Add(newReview);
    await db.SaveChangesAsync();
    return Results.Created($"/api/reviews/{newReview.Id}", newReview);
}).RequireAuthorization(); // Secured

app.MapPut("/api/reviews/{id}", async (ApplicationDbContext db, int id, [FromBody] Review updatedReview) =>
{
    var review = await db.Reviews.FindAsync(id);
    if (review is null) return Results.NotFound();
    if (!await db.Books.AnyAsync(b => b.Id == updatedReview.BookId)) return Results.BadRequest("Invalid BookId.");
    review.Rating = updatedReview.Rating;
    review.ReviewText = updatedReview.ReviewText;
    review.BookId = updatedReview.BookId;
    await db.SaveChangesAsync();
    return Results.Ok(review);
}).RequireAuthorization(); // Secured

app.MapDelete("/api/reviews/{id}", async (ApplicationDbContext db, int id) =>
{
    var review = await db.Reviews.FindAsync(id);
    if (review is null) return Results.NotFound();
    db.Reviews.Remove(review);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization(); // Secured

app.Run();
public record UserLogin(string Username, string Password);