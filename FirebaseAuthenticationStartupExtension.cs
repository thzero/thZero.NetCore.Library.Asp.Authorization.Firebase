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
using System.IO;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using FirebaseAdmin;
using FirebaseAdmin.Auth;
using Google.Apis.Auth.OAuth2;
using Microsoft.AspNetCore.Authorization;

namespace thZero.AspNetCore.Firebase
{
    public class FirebaseAuthenticationStartupExtension : AuthStartupExtension<FirebaseAuthorizationConfiguration>
    {
        #region Public Methods
        /// <summary>
        /// Set the environment variable GOOGLE_APPLICATION_CREDENTIALS with location of the Firebase Admin secret key config.
        /// </summary>
        public override void ConfigureServicesPre(IServiceCollection services, IWebHostEnvironment env, IConfiguration configuration)
        {
            base.ConfigureServicesPre(services, env, configuration);

            var pathToKey = Path.Combine(Directory.GetCurrentDirectory(), "keys", "firebase_admin_sdk.json");
            FirebaseApp.Create(new AppOptions
            {
                //Credential = GoogleCredential.FromFile(pathToKey)
                Credential = GoogleCredential.GetApplicationDefault()
            });
        }

        public override void ConfigureServicesInitializeAuthentication(IServiceCollection services, IWebHostEnvironment env, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = FirebaseAuthenticationOptions.AuthenticationScheme;
            })
            .AddFirebase(services);

            // TODO
            // Never returned either a OnAuthenticationFailed or OnTokenValidated.
            // Instead using a custom authentication that uses the FirebaseAuth's VerifyIdToken
            //services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            //    .AddJwtBearer("Firebase", options =>
            //    {
            //        var firebaseProjectId = Configuration["FirebaseProjectId"];
            //        options.Authority = "https://securetoken.google.com/" + firebaseProjectId;
            //        options.TokenValidationParameters = new TokenValidationParameters
            //        {
            //            ValidateIssuer = true,
            //            ValidIssuer = "https://securetoken.google.com/" + firebaseProjectId,
            //            ValidateAudience = true,
            //            ValidAudience = firebaseProjectId,
            //            ValidateLifetime = true
            //        };
            //        options.Events = new JwtBearerEvents()
            //        {
            //            OnAuthenticationFailed = c =>
            //            {
            //                Console.WriteLine(c.Exception.Message);
            //                // do some logging or whatever...
            //                return System.Threading.Tasks.Task.CompletedTask;
            //            },
            //            OnChallenge = context =>
            //            {
            //                Console.WriteLine("OnChallenge");
            //                // Skip the default logic.
            //                context.HandleResponse();

            //                var payload = new JObject
            //                {
            //                    ["error"] = context.Error,
            //                    ["error_description"] = context.ErrorDescription,
            //                    ["error_uri"] = context.ErrorUri
            //                };

            //                context.Response.ContentType = "application/json";
            //                context.Response.StatusCode = 401;

            //                //return context.Response.BodyWriter.WriteAsync(payload.ToString());
            //                // do some logging or whatever...
            //                return System.Threading.Tasks.Task.CompletedTask;
            //            },
            //            OnForbidden = c => {
            //                Console.WriteLine("OnForbidden");
            //                return System.Threading.Tasks.Task.CompletedTask;
            //            },
            //            OnMessageReceived = c =>
            //            {
            //                Console.WriteLine("OnMessageReceived");
            //                // do some logging or whatever...
            //                return System.Threading.Tasks.Task.CompletedTask;
            //            },
            //            OnTokenValidated = c =>
            //            {
            //                Console.WriteLine("OnTokenValidated");
            //                // do some logging or whatever...
            //                return System.Threading.Tasks.Task.CompletedTask;
            //            }
            //        };
            //    });
        }

        public override void ConfigureServicesInitializeAuthorization(IServiceCollection services, IWebHostEnvironment env, IConfiguration configuration)
        {
            services.AddAuthorization(
                options =>
                {
                    AuthorizationOptions(options);
                    AuthorizationOptionsDefaultPolicy(options);
                });
        }
        #endregion

        #region Protected Methods
        protected virtual void AuthorizationOptions(AuthorizationOptions options)
        {
            options.AddPolicy(FirebaseAuthenticationHandler.KeyPolicy,
                           builder =>
                           {
                                builder.AuthenticationSchemes.Add(FirebaseAuthenticationOptions.AuthenticationScheme);
                                //builder.RequireClaim(AdminApiKeyAuthorizeAttribute.KeyPolicy);
                                builder.RequireAuthenticatedUser();
                           });
        }

        protected virtual void AuthorizationOptionsDefaultPolicy(AuthorizationOptions options)
        {
            options.DefaultPolicy = options.GetPolicy(FirebaseAuthenticationHandler.KeyPolicy);
        }
        #endregion

        #region Protected Properties
        protected override string ConfigurationSectionKey => "Firebase";
        #endregion
    }

    public class FirebaseAuthenticationHandler : AuthenticationHandler<FirebaseAuthenticationOptions>
    {
        public FirebaseAuthenticationHandler(IOptionsMonitor<FirebaseAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IOptions<FirebaseAuthorizationConfiguration> config)
            : base(options, logger, encoder, clock)
        {
            _config = config.Value;
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

                //if (claims.Count == 0)
                //{
                //    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, no claims."));
                //    return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
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

                FirebaseToken token = await FirebaseAuth.DefaultInstance.VerifyIdTokenAsync(bearer);
                if (token == null)
                {
                    Logger.LogDebug(Logger.LogFormat(Declaration, "Authenticate: Failed, unverified token."));
                    //return Task.FromResult(AuthenticateResult.Fail("No apiKey."));
                    return AuthenticateResult.Fail("No unverified token.");
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
            //else if (Request.Headers.ContainsKey(KeyAuthorizationBearer))
            //    result = Request.Headers[KeyAuthorizationBearer];
            //else if (Request.Headers.ContainsKey(KeyAuthorizationBearer2))
            //    result = Request.Headers[KeyAuthorizationBearer2];

            return result;
        }
        #endregion

        #region Fields
        private readonly FirebaseAuthorizationConfiguration _config;
        #endregion

        #region Constants
        private const string KeyAuthorizationShardKey = "x-api-key";
        private const string KeyAuthorizationShardKey2 = "x-auth-key";
        private const string KeyAuthorizationBearer = "authorization";
        private const string KeyAuthorizationBearer2 = "Authorization";
        private const string PrefixBearer = "Bearer: ";
        #endregion

        #region Constants
        public const string KeyPolicy = "Firebase";
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
