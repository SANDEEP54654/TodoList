using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading.Tasks;
using TodoList.Data;
using TodoList.Models;

namespace TodoList.Controllers
{
    public class IdentityController : Controller
    {
        private readonly IMapper _mapper;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ApplicationDbContext _context;

        public IdentityController(IMapper mapper, UserManager<User> userManager, SignInManager<User> signInManager, ApplicationDbContext context)
        {
            _mapper = mapper;
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
        }

        [HttpGet]
        [Route("/identity/registration")]
        public IActionResult Registration()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction(nameof(TaskController.List), "Task");
            }
            return View();
        }

        [HttpPost]
        [Route("/identity/registration")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Registration(UserRegistrationModel userRegistrationModel)
        {
            if (!ModelState.IsValid)
            {
                return View(userRegistrationModel);
            }

            var user = _mapper.Map<User>(userRegistrationModel);

            IdentityResult result = await _userManager.CreateAsync(user, userRegistrationModel.Password1);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }

                return View(userRegistrationModel);
            }

            return RedirectToAction(nameof(HomeController.Home), "Home");
        }

        [HttpGet]
        [Route("/identity/login")]
        [ActionName("Login")]
        public IActionResult Login(string ReturnUrl = null)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction(nameof(TaskController.List), "Task");
            }

            ViewData["ReturnUrl"] = ReturnUrl;
            return View();
        }

        [HttpPost]
        [Route("/identity/login")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(UserLoginModel userLoginModel, string ReturnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(userLoginModel);
            }

            var result = await _signInManager.PasswordSignInAsync(userLoginModel.Email, userLoginModel.Password, userLoginModel.RememberMe, false);

            if (result.Succeeded)
            {
                return RedirectToLocal(ReturnUrl);
            }
            else
            {
                ModelState.AddModelError("", "Invalid email or Password");
                return View(userLoginModel);
            }

        }

        [HttpGet]
        [Route("/identity/logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Home), "Home");
        }


        [Authorize]
        [HttpGet]
        [Route("/identity/change-password")]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [Authorize]
        [HttpPost]
        [Route("/identity/change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel changePasswordModel)
        {
            if (!ModelState.IsValid)
            {
                return View(changePasswordModel);
            }

            var currentUser = await _userManager.FindByNameAsync(User.Identity.Name);
            var resultChangePassword = await _userManager.ChangePasswordAsync(currentUser, changePasswordModel.OldPassword, changePasswordModel.Password2);
            if (!resultChangePassword.Succeeded)
            {
                foreach (var error in resultChangePassword.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }
                return View(changePasswordModel);
            }
            await _signInManager.SignOutAsync();
            TempData["PasswordChangeOk"] = "Password was successfully changed";
            return RedirectToAction(nameof(Login), "Identity");
        }

        [Authorize]
        [HttpGet]
        [Route("/identity/delete-user")]
        public IActionResult ConfirmDeleteUser()
        {
            return View("DeleteUser");
        }

        [Authorize]
        [HttpPost]
        [Route("/identity/delete-user")]
        public async Task<IActionResult> DeleteUser()
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            var userTasks = await _context.Tasks.Where(t => t.User == user).ToListAsync();
            _context.RemoveRange(userTasks);

            await _signInManager.SignOutAsync();
            await _userManager.DeleteAsync(user);
            return RedirectToAction(nameof(Registration), "Identity");
        }

        [Authorize]
        [Route("/identity/settings")]
        public IActionResult Settings()
        {
            return View();
        }

        [NonAction]
        private IActionResult RedirectToLocal(string ReturnUrl)
        {
            if (Url.IsLocalUrl(ReturnUrl))
            {
                return Redirect(ReturnUrl);
            }
            else
            {
                return RedirectToAction("List", "Task");
            }
        }
    }
}