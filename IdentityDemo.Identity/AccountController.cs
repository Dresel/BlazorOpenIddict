using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityDemo.Identity
{
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        [HttpGet("login")]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null!)
        {
            return Ok();
        }
	}
}
