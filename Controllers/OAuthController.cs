using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using RequestsNET;
using asp_core_oauth.Models;

namespace asp_core_oauth.Controllers
{
    public struct Scope
    {
        public string Desc;
        public string Value;
    }

    public class OAuthController : Controller
    {
        private const string CLIENT_STATE = "test123";
        private const string CLIENT_ID = "Bobs Socks";
        private const string CLIENT_SECRET = "shh";
        private readonly Dictionary<string, string> CLIENT_IDS = new Dictionary<string, string>{{CLIENT_ID, CLIENT_SECRET}};
        private const string SOCKS = "socks";
        private const string SHOES = "shoes";
        private readonly Dictionary<string, Scope> SCOPES = new Dictionary<string, Scope>{{SOCKS, new Scope{ Desc="sock inventory", Value="pinstripe business socks, woolen socks"}}, {SHOES, new Scope{ Desc="shoe inventory", Value="red ruby shoes"}}};

        // TODO: example only in memory data stores for oauth tokens
        private static readonly Dictionary<string, OAuthRequestViewModel> _requests = new Dictionary<string, OAuthRequestViewModel>();
        private static readonly Dictionary<string, OAuthTokenViewModel> _tokens = new Dictionary<string, OAuthTokenViewModel>();

        private readonly ILogger<OAuthController> _logger;

        public OAuthController(ILogger<OAuthController> logger)
        {
            _logger = logger;
        }

        string CreateToken(int len) {
            using(var rng = new RNGCryptoServiceProvider()) {
                var bytes = new byte[len];
                rng.GetBytes(bytes);
                return Convert.ToBase64String(bytes);
            }
        }

        //
        // OAuth client endpoints
        //

        public IActionResult Index()
        {
            ViewData["STATE"] = CLIENT_STATE;
            ViewData["CLIENT_ID"] = CLIENT_ID;
            ViewData["SCOPES"] = SCOPES;
            return View();
        }

        public async Task<IActionResult> Callback(string code, string state)
        {
            if (state != CLIENT_STATE)
                return BadRequest("invalid state");
            var url = Url.Action("Token", "OAuth", null, Request.Scheme);
            var redirectUri = Url.Action("Callback", "OAuth", null, Request.Scheme);
            var resp = await Requests.Post(url)
                              .Form("grant_type", "authorization_code")
                              .Form("code", code)
                              .Form("redirect_uri", redirectUri)
                              .Form("client_id", CLIENT_ID)
                              .Form("client_secret", CLIENT_SECRET)
                              .ExecuteAsync();
            var result = resp.Json.ToString();
            var token = resp.Json.ToObject<OAuthTokenViewModel>();
            if (token.Scope == SOCKS)
            {
                url = Url.Action("Socks", "OAuth", null, Request.Scheme);
                try
                {
                    resp = await Requests.Get(url)
                        .Header("Authorization", "Bearer " + token.AccessToken)
                        .ExecuteAsync();
                    result += "\n\n" + resp.Text;
                }
                catch
                {
                    result += "\n\nError accessing " + url; 
                }
            }
            if (token.Scope == SHOES)
            {
                url = Url.Action("Shoes", "OAuth", null, Request.Scheme);
                try
                {
                    resp = await Requests.Get(url)
                        .Header("Authorization", "Bearer " + token.AccessToken)
                        .ExecuteAsync();
                    result += "\n\n" + resp.Text;
                }
                catch
                {
                    result += "\n\nError accessing " + url; 
                }
            }
            return Ok(result);
        }

        //
        // OAuth provider endpoints
        //

        public IActionResult Auth([FromQuery]OAuthRequestViewModel model)
        {
            //
            // TODO: NOTE! - ensure the user is logged in before allowing access to this endpoint
            //

            // validate response_type
            if (model.ResponseType != "code")
                return BadRequest("invalid response_type");
            // valid client_id
            if (!CLIENT_IDS.ContainsKey(model.ClientId))
                return BadRequest("invalid client_id");
            // valid scope
            if (string.IsNullOrEmpty(model.Scope))
                return BadRequest("invalid scope");
            foreach (var scope in model.Scope.Split(' '))
                if (!SCOPES.ContainsKey(scope))
                    return BadRequest("invalid scope");

            model.Allow = false;
            model.Code = CreateToken(8);
            _requests[model.Code] = model;

            ViewData["SCOPES"] = SCOPES;
            return View(model);
        }

        [HttpPost]
        public IActionResult Deny([FromForm] string code)
        {
            if (!_requests.ContainsKey(code))
                return BadRequest("invalid code");
            var req = _requests[code];
            _requests.Remove(code);
            return Redirect(req.RedirectUri);
        }

        [HttpPost]
        public IActionResult Allow([FromForm] string code)
        {
            if (!_requests.ContainsKey(code))
                return BadRequest("invalid code");
            var req = _requests[code];
            if (req.Allow)
                return BadRequest("already allowed");
            req.Allow = true;
            var uri = string.Format("{0}?code={1}&state={2}", req.RedirectUri, Uri.EscapeDataString(req.Code), Uri.EscapeDataString(req.State));
            return Redirect(uri);
        }

        [HttpPost]
        [Produces("application/json")]
        public ActionResult<OAuthTokenViewModel> Token([FromForm] OAuthTokenRequestViewModel model)
        {
            if (model.GrantType != "authorization_code")
                return BadRequest(new OAuthTokenErrorViewModel{ Error = string.Format("invalid grant type ({0})", model.GrantType) });
            if (!_requests.ContainsKey(model.Code))
                return BadRequest(new OAuthTokenErrorViewModel{ Error = "invalid code" });
            var req = _requests[model.Code];
            if (!req.Allow)
                return BadRequest(new OAuthTokenErrorViewModel{ Error = "invalid request" });
            if (req.ClientId != model.ClientId || model.ClientSecret != CLIENT_IDS[model.ClientId])
                return BadRequest(new OAuthTokenErrorViewModel{ Error = "invalid client id" });
            if (req.RedirectUri != model.RedirectUri)
                return BadRequest(new OAuthTokenErrorViewModel{ Error = "invalid redirect uri" });
            var expiryIn = 60 * 60 * 24 * 7;
            var expiryAt = DateTimeOffset.Now.AddSeconds(expiryIn).ToUnixTimeSeconds();
            var token = new OAuthTokenViewModel{ AccessToken = CreateToken(16), ExpiresIn = expiryIn, ExpiresAt = expiryAt, Scope = req.Scope };
            _tokens[token.AccessToken] = token;
            return token;
        }

        //
        // OAuth authorized resources
        //

        OAuthTokenViewModel CheckAuth()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return null;
            var authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader))
                return null;
            if (!authHeader.StartsWith("Bearer "))
                return null;
            var accessToken = authHeader.Substring(7);
            if (!_tokens.ContainsKey(accessToken))
                return null;
            var token = _tokens[accessToken];
            if (token.ExpiresAt < DateTimeOffset.Now.ToUnixTimeSeconds())
                return null;

            //
            // TODO: NOTE! from here we should get the user associated with this token to access their specific resources
            //

            return token;
        }

        bool CheckScope(string allowedScopes, string requestedScope)
        {
            foreach (var scope in allowedScopes.Split(' '))
                if (scope == requestedScope)
                    return true;
            return false;
        }

        public IActionResult Validate()
        {
            if (CheckAuth() == null)
                return Unauthorized();
            return Ok();
        }

        public IActionResult Socks()
        {
            var token = CheckAuth();
            if (token == null)
                return Unauthorized();
            if (!CheckScope(token.Scope, SOCKS))
                return Unauthorized();
            return Ok(SCOPES[SOCKS].Value);
        }

        public IActionResult Shoes()
        {
            var token = CheckAuth();
            if (token == null)
                return Unauthorized();
            if (!CheckScope(token.Scope, SHOES))
                return Unauthorized();
            return Ok(SCOPES[SHOES].Value);
        }
    }
}
