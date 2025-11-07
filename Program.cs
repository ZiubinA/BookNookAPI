using BookNookAPI;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//DATABASE SETUP
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
});

//JSON CONFIG
builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
{
    options.SerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
});

//AUTHENTICATION (JWT)
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            
            RoleClaimType = ClaimTypes.Role 
        };
    });

//AUTHORIZATION (POLICIES)
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

//SWAGGER
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "BookNook API", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { new OpenApiSecurityScheme { Reference = new OpenApiReference { Type=ReferenceType.SecurityScheme, Id="Bearer" } }, new string[]{} }
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

//LOGIN ENDPOINT (UPDATED) 
app.MapPost("/api/login", (UserLogin loginAttempt, IConfiguration config) =>
{
    var users = new List<MockUser>
    {
        new MockUser("admin", "admin123", "Admin", "100"),     
        new MockUser("user1", "user123", "User", "101"),       
        new MockUser("alice", "password", "User", "102")      
    };

    var user = users.FirstOrDefault(u => u.Username == loginAttempt.Username && u.Password == loginAttempt.Password);

    if (user is null) return Results.Unauthorized();

    // Create Token with Role and Id claims
    var key = Encoding.ASCII.GetBytes(config["Jwt:Key"]!);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            new Claim(ClaimTypes.Role, user.Role), 
            new Claim("UserId", user.UserId)        
        }),
        Expires = DateTime.UtcNow.AddHours(2),
        Issuer = config["Jwt:Issuer"],
        Audience = config["Jwt:Audience"],
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
    };
    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
    return Results.Ok(new { token, user.Role, user.UserId });
});

//  AUTHORS (Admin Only for Changes)
app.MapGet("/api/authors", async (ApplicationDbContext db) => 
    await db.Authors.Include(a => a.Books).ToListAsync());

app.MapGet("/api/authors/{id}", async (ApplicationDbContext db, int id) =>
    await db.Authors.Include(a => a.Books).FirstOrDefaultAsync(a => a.Id == id) is Author author ? Results.Ok(author) : Results.NotFound());

// SECURED: Only Admins can create/edit/delete authors
app.MapPost("/api/authors", async (ApplicationDbContext db, Author author) => {
    db.Authors.Add(author); await db.SaveChangesAsync(); return Results.Created($"/api/authors/{author.Id}", author);
}).RequireAuthorization("AdminOnly");

app.MapPut("/api/authors/{id}", async (ApplicationDbContext db, int id, Author updated) => {
    var a = await db.Authors.FindAsync(id); if (a is null) return Results.NotFound();
    a.Name = updated.Name; await db.SaveChangesAsync(); return Results.Ok(a);
}).RequireAuthorization("AdminOnly");

app.MapDelete("/api/authors/{id}", async (ApplicationDbContext db, int id) => {
    var a = await db.Authors.FindAsync(id); if (a is null) return Results.NotFound();
    db.Authors.Remove(a); await db.SaveChangesAsync(); return Results.NoContent();
}).RequireAuthorization("AdminOnly");

// BOOKS (Admin Only for Changes)
app.MapGet("/api/books", async (ApplicationDbContext db) => 
    await db.Books.Include(b => b.Author).Include(b => b.Reviews).ToListAsync());

app.MapGet("/api/books/{id}", async (ApplicationDbContext db, int id) =>
    await db.Books.Include(b => b.Author).Include(b => b.Reviews).FirstOrDefaultAsync(b => b.Id == id) is Book book ? Results.Ok(book) : Results.NotFound());

// SECURED: Only Admins can create/edit/delete books
app.MapPost("/api/books", async (ApplicationDbContext db, Book book) => {
    if (!await db.Authors.AnyAsync(a => a.Id == book.AuthorId)) return Results.BadRequest("Invalid AuthorId");
    db.Books.Add(book); await db.SaveChangesAsync(); return Results.Created($"/api/books/{book.Id}", book);
}).RequireAuthorization("AdminOnly");

app.MapPut("/api/books/{id}", async (ApplicationDbContext db, int id, Book updated) => {
    var b = await db.Books.FindAsync(id); if (b is null) return Results.NotFound();
    b.Title = updated.Title; b.Genre = updated.Genre; b.Description = updated.Description; b.AuthorId = updated.AuthorId;
    await db.SaveChangesAsync(); return Results.Ok(b);
}).RequireAuthorization("AdminOnly");

app.MapDelete("/api/books/{id}", async (ApplicationDbContext db, int id) => {
    var b = await db.Books.FindAsync(id); if (b is null) return Results.NotFound();
    db.Books.Remove(b); await db.SaveChangesAsync(); return Results.NoContent();
}).RequireAuthorization("AdminOnly");

// REVIEWS (User owned, Admin managed)
app.MapGet("/api/reviews", async (ApplicationDbContext db) => await db.Reviews.Include(r => r.Book).ToListAsync());

app.MapPost("/api/reviews", [Authorize] async (ApplicationDbContext db, ClaimsPrincipal user, Review review) =>
{
    if (!await db.Books.AnyAsync(b => b.Id == review.BookId)) return Results.BadRequest("Invalid BookId.");
    var userId = user.FindFirstValue("UserId");
    review.UserId = userId; 

    db.Reviews.Add(review);
    await db.SaveChangesAsync();
    return Results.Created($"/api/reviews/{review.Id}", review);
});

app.MapPut("/api/reviews/{id}", [Authorize] async (ApplicationDbContext db, ClaimsPrincipal user, int id, Review updated) =>
{
    var review = await db.Reviews.FindAsync(id);
    if (review is null) return Results.NotFound();
    var currentUserId = user.FindFirstValue("UserId");
    var isAdmin = user.IsInRole("Admin");

    if (review.UserId != currentUserId && !isAdmin)
    {
        return Results.Forbid(); 
    }

    review.Rating = updated.Rating;
    review.ReviewText = updated.ReviewText;
    await db.SaveChangesAsync();
    return Results.Ok(review);
});

// DELETE REVIEW
app.MapDelete("/api/reviews/{id}", [Authorize] async (ApplicationDbContext db, ClaimsPrincipal user, int id) =>
{
    var review = await db.Reviews.FindAsync(id);
    if (review is null) return Results.NotFound();

    var currentUserId = user.FindFirstValue("UserId");
    var isAdmin = user.IsInRole("Admin");

    if (review.UserId != currentUserId && !isAdmin)
    {
         return Results.Forbid();
    }

    db.Reviews.Remove(review);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.Run();

// Helper records
public record UserLogin(string Username, string Password);
public record MockUser(string Username, string Password, string Role, string UserId);