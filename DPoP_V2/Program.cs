using DPoP_V2;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddTransient<DPoPAccessTokenService>();
builder.Services.AddTransient<DPopHeaderService>();
builder.Services.AddTransient<DPoPProtectedResourceRequestService>();
builder.Services.AddTransient<ClientService>();
builder.Services.AddTransient<AuthorizationServerService>();
builder.Services.AddTransient<ResourceServerService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
