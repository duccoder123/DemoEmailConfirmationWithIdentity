using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DemoEmailConfirmationWithIdentity.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
    {

        private async Task<IdentityUser>? GetUser(string email) => await userManager.FindByEmailAsync(email);

        [HttpPost("register/{email}/{password}")]
        public async Task<IActionResult> Register (string email, string password)
        {

            var user = await GetUser(email);

            if (user is not null) return BadRequest();

            var result = await userManager.CreateAsync(new IdentityUser()
            {
                UserName = email,
                Email = email,
                PasswordHash = password
            }, password);

            if (!result.Succeeded) return BadRequest();

            var _user = await GetUser(email);
            var emailCode = await userManager.GenerateEmailConfirmationTokenAsync(_user!);

            string sendEmail = SendEmail(_user!.Email, emailCode);   
            return Ok(sendEmail);
        }

        private string SendEmail(string email, string code) {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("<html>");
            sb.AppendLine("<body>");
            sb.AppendLine($"<p>Dear, {email}</p>");
            sb.AppendLine("<p>Thank you for registering with us. To verify your email address, please check it if u wanna continue : </p>");
            sb.AppendLine($"<h2>Verification Code : {code}</h2>");
            sb.AppendLine("<p>Please enter this code on our website to complete your registeration</p>");
            sb.AppendLine("<p>If you didn't request this, please ignore this email.</p>");
            sb.AppendLine("<br>");
            sb.AppendLine("<p>Best regards, </p>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            string message = sb.ToString();
            var _email = new MimeMessage();
            _email.To.Add(MailboxAddress.Parse("lazaro93@ethereal.email"));
            _email.From.Add(MailboxAddress.Parse("lazaro93@ethereal.email"));
            _email.Subject = "Email Confirmation";
            _email.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message };

                using var smtp = new SmtpClient();
                smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
                smtp.Authenticate("lazaro93@ethereal.email", "jFpZYxQw672V4NkSDB");
                smtp.Send(_email);
            smtp.Disconnect(true);
            return "Thank you for your registeration, kindly check your email for confirmation code";
        }

        [HttpPost("confirmation/{email}/{code:int}")]
        public async Task<IActionResult> Confirmation (string email, int code)
        {
            if (string.IsNullOrEmpty(email) || code <= 0) return BadRequest("Invalid code provided");

            var user = await GetUser(email);

            if (user is null) return BadRequest("Invalid identity provided");

            var result = await userManager.ConfirmEmailAsync(user, code.ToString());

            if (!result.Succeeded)
                return BadRequest("Invalid code provided");
            else
                return Ok("Email confirmed successfully, you can processed to login");

        }



        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> Login (string email, string password)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
                return BadRequest();

            var user = await GetUser(email);

            bool isEmailConfirmed = await userManager.IsEmailConfirmedAsync(user!);

            if (!isEmailConfirmed) return BadRequest("You need to confirm email before logging ");
            
            return Ok(new[] {"login successfully", GenerateToken(user)});  
        }

        private string GenerateToken(IdentityUser user)
        {
            byte[] key = Encoding.UTF8.GetBytes("Abcxyz123456789QWERTyuiopzxczxcxzc");
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Email, user!.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user!.Id)
            };

            var token = new JwtSecurityToken(
                    issuer: null,
                    audience: null,
                    signingCredentials: credentials,
                    claims: claims,
                    expires: null
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        [HttpGet("protected")]
        [Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme)]
        public string GetMessage() => "This message is coming from protected endpoint";


    }
}
