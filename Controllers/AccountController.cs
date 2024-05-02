using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Auth0.ManagementApi;
using Auth0.ManagementApi.Models;

namespace Auth0Application.Controllers;

public class AccountController : Controller
{
    private readonly IManagementApiClient _managementApiClient;
    public AccountController(IManagementApiClient managementApiClient)
    {
        _managementApiClient = managementApiClient;
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

    [Route("/account/login")]
    public async Task Login(string returnUrl = "/home")
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
            .WithRedirectUri(Url.Action("Index", "Home", null, "http"))
            .Build();

        await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        Response.Cookies.Delete(".AspNetCore.Cookies");
    }

    [Authorize]
    [Route("/account/profile")]
    public async Task<IActionResult> Profile()
    {
        var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
        var user = await _managementApiClient.Users.GetAsync(userId);

        return View(user);
    }

    [Authorize]
    [Route("/account/profile/edit")]
    public async Task<IActionResult> EditProfile()
    {
        var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
        var user = await _managementApiClient.Users.GetAsync(userId);

        return View(user);
    }

    [Authorize]
    [HttpPost("/account/profile/edit")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SubmitEditProfile([FromForm] UserUpdateRequest updateReq)
    {
        var userId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
        var updatedUser = await _managementApiClient.Users.UpdateAsync(userId, updateReq);

        return Redirect(Url.Action("Profile", "Account"));
    }

    [Authorize]
    [Route("/account/allUsers")]
    public async Task<IActionResult> GetAllUsers()
    {
        GetUsersRequest getUsersRequest = new();
        var allUsers = await _managementApiClient.Users.GetAllAsync(getUsersRequest);
        return View(allUsers);
    }

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
}
