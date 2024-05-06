using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Auth0.ManagementApi;
using Auth0.AspNetCore.Authentication;

namespace Auth0Application.Controllers;

public class AccountController : Controller
{
    private readonly IManagementApiClient _managementApiClient;
    private readonly IConfiguration _configuration;
    public AccountController(IManagementApiClient managementApiClient, IConfiguration configuration)
    {
        _managementApiClient = managementApiClient;
        _configuration = configuration;
    }

    [Route("/account/signup")]
    public async Task Signup(string returnUrl = "/home")
    {
        var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
            .WithParameter("screen_hint", "signup")
            .WithRedirectUri(returnUrl)
            .Build();

        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    }

    [Route("account/callback")]
    public async Task<IActionResult> Callback()
    {
        string name = "";
        if (User.Identity.IsAuthenticated)
        {
            name = User.Identity.Name;
        }
        else
        {
            name = User.Claims.FirstOrDefault(x => x.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")).Subject.Name ?? string.Empty;
        }

        string ssoContent;
        if (!string.IsNullOrEmpty(name))
        {
            ssoContent = GetSSOContent(name);
            var portalLogin = _configuration["Auth0:PortalUri"];
            return Redirect($"{portalLogin}/idplogin?e={ssoContent}");
        }
        return Redirect("/home");
    }

    [Route("/account/login")]
    public async Task Login(string returnUrl = "/account/callback")
    {
        var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
            .WithRedirectUri(returnUrl)
            .Build();

        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    }

    [Authorize]
    [Route("/account/logout")]
    public async Task Logout()
    {
        var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
            .WithRedirectUri(Url.Action("Index", "Home", null, "https"))
            .Build();

        await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        Response.Cookies.Delete(".AspNetCore.Cookies");
    }

    //[Authorize]
    //[Route("/account/profile")]
    //public async Task<IActionResult> Profile()
    //{
    //    var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    //    var user = await _managementApiClient.Users.GetAsync(userId);

    //    return View(user);
    //}

    //[Authorize]
    //[Route("/account/profile/edit")]
    //public async Task<IActionResult> EditProfile()
    //{
    //    var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    //    var user = await _managementApiClient.Users.GetAsync(userId);

    //    return View(user);
    //}

    //[Authorize]
    //[HttpPost("/account/profile/edit")]
    //[ValidateAntiForgeryToken]
    //public async Task<IActionResult> SubmitEditProfile([FromForm] UserUpdateRequest updateReq)
    //{
    //    var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    //    var updatedUser = await _managementApiClient.Users.UpdateAsync(userId, updateReq);

    //    return Redirect(Url.Action("Profile", "Account"));
    //}

    //[Authorize]
    //[Route("/account/allUsers")]
    //public async Task<IActionResult> GetAllUsers()
    //{
    //    GetUsersRequest getUsersRequest = new();
    //    var allUsers = await _managementApiClient.Users.GetAllAsync(getUsersRequest);
    //    return View(allUsers);
    //}

    [Route("/account/access-denied")]
    public IActionResult AccessDenied()
    {
        return View();
    }

    [Route("/account/email-verification")]
    public IActionResult EmailVerificationNeeded()
    {
        return View();
    }

    private string GetSSOContent(string name, string page = "", int orderId = -1, string clientName = "")
    {
        var content = new SsoContent
        {
            EmailAddress = ToBase64Encode(name),
            Issuer = ToBase64Encode(_configuration["Auth0:Issuer"]),
            TargetPage = page,
            OrderPKey = orderId,
            Expiration = DateTime.Now.AddSeconds(5),
            ClientName = clientName
        };

        var serializerOptions = new JsonSerializerOptions
        {
            AllowTrailingCommas = true,
            ReadCommentHandling = JsonCommentHandling.Skip
        };
        var ssoContentJson = JsonSerializer.Serialize(content, serializerOptions);
        var encodedData = ToBase64Encode(ssoContentJson);
        return encodedData;
    }

    public static string ToBase64Encode(string text)
    {
        if (String.IsNullOrEmpty(text))
        {
            return text;
        }

        byte[] textBytes = Encoding.UTF8.GetBytes(text);
        return Convert.ToBase64String(textBytes);
    }

    public static string ToBase64Decode(string base64EncodedText)
    {
        if (String.IsNullOrEmpty(base64EncodedText))
        {
            return base64EncodedText;
        }

        byte[] base64EncodedBytes = Convert.FromBase64String(base64EncodedText);
        return Encoding.UTF8.GetString(base64EncodedBytes);
    }

    public class SsoContent
    {
        public string EmailAddress { get; set; }
        public string Issuer { get; set; }
        public string ClientName { get; set; }
        public string TargetPage { get; set; }
        public int OrderPKey { get; set; }
        public DateTime Expiration { get; set; }
    }
}


