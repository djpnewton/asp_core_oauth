using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;
using Newtonsoft.Json;

namespace asp_core_oauth.Models
{
    public class OAuthRequestViewModel
    {
        public bool Allow { get; set; }
        public string Code { get; set; }
        [FromQuery(Name = "client_id")]
        public string ClientId { get; set; }
        [FromQuery(Name = "response_type")]
        public string ResponseType { get; set; }
        [FromQuery(Name = "redirect_uri")]
        public string RedirectUri { get; set; }
        [FromQuery(Name = "scope")]
        public string Scope { get; set; }
        [FromQuery(Name = "state")]
        public string State { get; set; }
    }

    public class OAuthTokenRequestViewModel {
        [FromQuery(Name = "grant_type")]
        public string GrantType { get; set; }
        [Required]
        [FromQuery(Name = "code")]
        public string Code { get; set; }
        [FromQuery(Name = "redirect_uri")]
        public string RedirectUri { get; set; }
        [FromQuery(Name = "client_id")]
        public string ClientId { get; set; }
        [FromQuery(Name = "client_secret")]
        public string ClientSecret { get; set; }
    }

    public class OAuthTokenViewModel {
        [JsonProperty("access_token")]
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }
        [JsonProperty("expires_in")]
        [JsonPropertyName("expires_in")]
        public long ExpiresIn { get; set; }
        [JsonProperty("expires_at")]
        [JsonPropertyName("expires_at")]
        public long ExpiresAt { get; set; }
        [JsonProperty("scope")]
        [JsonPropertyName("scope")]
        public string Scope { get; set; }
    }

    public class OAuthTokenErrorViewModel {
        [JsonProperty("error")]
        [JsonPropertyName("error")]
        public string Error { get; set; }
    }
}
