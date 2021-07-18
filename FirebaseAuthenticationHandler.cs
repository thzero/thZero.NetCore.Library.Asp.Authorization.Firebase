/* ------------------------------------------------------------------------- *
thZero.NetCore.Library.Asp.Authorization.Firebase
Copyright (C) 2016-2021 thZero.com

<development [at] thzero [dot] com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 * ------------------------------------------------------------------------- */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using FirebaseAdmin.Auth;

using Nito.AsyncEx;

using thZero.Instrumentation;

namespace thZero.AspNetCore.Firebase
{
    public class FirebaseAuthenticationHandler : AuthenticationHandler<FirebaseAuthenticationOptions>
    {
        public FirebaseAuthenticationHandler(Services.Authorization.IAuthorizationService authService, IMemoryCache memoryCache, IOptionsMonitor<FirebaseAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IOptions<FirebaseAuthorizationConfiguration> config)
            : base(options, logger, encoder, clock)
        {
            Enforce.AgainstNull(() => config);
            Enforce.AgainstNull(() => authService);

            _config = config.Value;
            Enforce.AgainstNull(() => _config);

            _serviceAuth = authService;

            _cache = memoryCache;
        }

        #region Protected Methods
        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            const string Declaration = "HandleAuthenticateAsync";

            try
            {
                var sharedKey = CheckParameterAuthorizationSharedKey();
                Logger.LogDebug(Logger.LogFormat(Declaration, "authHeader", () => { return sharedKey; }));
                if (string.IsNullOrEmpty(sharedKey))
                {
                    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed."));
                    return AuthenticateResult.Fail("No apiKey.");
                }

                if (!_config.Key.Equals(sharedKey))
                {
                    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, shared api key invalid."));
                    return AuthenticateResult.Fail("Invalid apiKey.");
                }

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, FirebaseAuthenticationOptions.AuthenticationScheme)
                };
                //if (_config.Authorization.Key.Equals(authHeader))
                //    claims.Add(new Claim(ApiKeyAuthorizeAttribute.KeyPolicy, authHeader));
                //if (_config.Authorization.KeyAdmin.Equals(authHeader))
                //{
                //    claims.Add(new Claim(ApiKeyAuthorizeAttribute.KeyPolicy, authHeader));
                //    claims.Add(new Claim(AdminApiKeyAuthorizeAttribute.KeyPolicy, authHeader));
                //}

                string bearer = CheckParameterAuthorizationBearer();
                if (String.IsNullOrEmpty(bearer))
                {
                    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, no authorization key."));
                    //return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
                    return AuthenticateResult.Fail("No authorization key.");
                }

                bearer = bearer.Replace(PrefixBearer, String.Empty);
                if (String.IsNullOrEmpty(bearer))
                {
                    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, no bearer token."));
                    //return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
                    return AuthenticateResult.Fail("No bearer token.");
                }

                FirebaseToken token = await GetTokenAsync(bearer);
                if (token == null)
                {
                    token = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(bearer);
                    if (token == null)
                    {
                        Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, unverified token."));
                        //return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
                        return AuthenticateResult.Fail("Unverified token.");
                    }

                    if (String.IsNullOrEmpty(token.Uid))
                    {
                        Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, token is missing user id."));
                        //return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
                        return AuthenticateResult.Fail("Token missing user id.");
                    }
                }

                long expiration = token.ExpirationTimeSeconds - token.IssuedAtTimeSeconds;
                await SetTokenAsync(bearer, token, (expiration * 1000) - 250);

                await FetchClaimsAsync(Context.RequestServices.GetService<IInstrumentationPacket>(), claims, token.Uid);
                if (claims.Count == 0)
                {
                    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, no claims."));
                    return AuthenticateResult.Fail("No claims.");
                }

                var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, FirebaseAuthenticationOptions.AuthenticationScheme));
                var ticket = new AuthenticationTicket(principal, FirebaseAuthenticationOptions.AuthenticationScheme);

                Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Success."));
                //return Task.FromResult(AuthenticateResult.Success(ticket));
                return AuthenticateResult.Success(ticket);
            }
            catch (Exception ex)
            {
                Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed.", ex));
                //return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
                return AuthenticateResult.Fail("No apiKey.");
            }
        }

        protected virtual async Task FetchClaimsAsync(IInstrumentationPacket instrumentation, List<Claim> claims, string userId)
        {
            await _serviceAuth.HandleAuthenticateAsync(instrumentation, claims, userId);
        }
        #endregion

        #region Private Methods
        private string CheckParameterAuthorizationBearer()
        {
            string result = null;
            if (Request.Headers.ContainsKey(KeyAuthorizationBearer))
                result = Request.Headers[KeyAuthorizationBearer];
            else if (Request.Headers.ContainsKey(KeyAuthorizationBearer2))
                result = Request.Headers[KeyAuthorizationBearer2];

            return result;
        }

        private string CheckParameterAuthorizationSharedKey()
        {
            string result = null;
            if (Request.Headers.ContainsKey(KeyAuthorizationShardKey))
                result = Request.Headers[KeyAuthorizationShardKey];
            else if (Request.Headers.ContainsKey(KeyAuthorizationShardKey2))
                result = Request.Headers[KeyAuthorizationShardKey2];

            return result;
        }

        private async Task<FirebaseToken> GetTokenAsync(string key)
        {
            IDisposable release = null;
            try
            {
                release = await _mutex.ReaderLockAsync();

                FirebaseToken token;
                _cache.TryGetValue(key, out token);
                return token;
            }
            finally
            {
                if (release != null)
                    release.Dispose();
            }
        }

        private async Task SetTokenAsync(string key, FirebaseToken token, long expiration)
        {
            IDisposable release = null;
            try
            {
                release = await _mutex.WriterLockAsync();

                _cache.Set(key, token,
                    // Keep in cache for this time, reset time if accessed.
                    new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromMilliseconds(expiration)));
            }
            finally
            {
                if (release != null)
                    release.Dispose();
            }
        }
        #endregion

        #region Fields
        private readonly FirebaseAuthorizationConfiguration _config;
        private readonly Services.Authorization.IAuthorizationService _serviceAuth;

        private readonly IMemoryCache _cache;
        private readonly AsyncReaderWriterLock _mutex = new();
        #endregion

        #region Constants
        private const string KeyAuthorizationShardKey = "x-api-key";
        private const string KeyAuthorizationShardKey2 = "x-auth-key";
        private const string KeyAuthorizationBearer = "authorization";
        private const string KeyAuthorizationBearer2 = "Authorization";
        private const string PrefixBearer = "Bearer: ";
        #endregion
    }

    public class FirebaseAuthenticationOptions : AuthenticationSchemeOptions
    {
        #region Public Methods
        public override void Validate()
        {
            Console.WriteLine("");
        }
        #endregion

        #region Constants
        public const string AuthenticationScheme = "Firebase";
        #endregion
    }

    public static class FirebaseAuthenticationHandlerExtensions
    {
        #region Public Methods
        public static AuthenticationBuilder AddFirebase(this AuthenticationBuilder builder, IServiceCollection services)
        {
            return builder.AddScheme<FirebaseAuthenticationOptions, FirebaseAuthenticationHandler>(
                FirebaseAuthenticationOptions.AuthenticationScheme, // Name of scheme
                FirebaseAuthenticationOptions.AuthenticationScheme, // Display name of scheme
                options =>
                {
                    //var provider = services.BuildServiceProvider();
                    // Logger, ServiceUserRepository and SharedKeyAuthenticationProcess are all things that were injected into the custom authentication
                    // middleware in ASP.NET Core 1.1. This is now added to the options object instead.
                    //options.Logger = provider.GetService<global::Serilog.ILogger>();
                    //options.ServiceUserRepository = provider.GetService<IServiceUserRepository>();
                    //options.SharedKeyAuthenticationProcess = provider.GetService<ISharedKeyAuthenticationProcess>();
                });
        }
        #endregion
    }

    public class FirebaseAuthorizationConfiguration : AuthorizationConfiguration
    {
        #region Public Properties
        public string Key { get; set; }
        #endregion
    }
}
