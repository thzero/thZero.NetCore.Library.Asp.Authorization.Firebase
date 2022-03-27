/* ------------------------------------------------------------------------- *
thZero.NetCore.Library.Asp.Authorization.Firebase
Copyright (C) 2016-2022 thZero.com

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
using System.IO;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;

namespace thZero.AspNetCore.Firebase
{
    public abstract class FirebaseAuthenticationStartupExtension<TAuthorizationService> : AuthStartupExtension<FirebaseAuthorizationConfiguration>
        where TAuthorizationService : class, Services.Authorization.IAuthorizationService
    {
        #region Public Methods
        /// <summary>
        /// Set the environment variable GOOGLE_APPLICATION_CREDENTIALS with location of the Firebase Admin secret key config.
        /// </summary>
        public override void ConfigureServicesPre(IServiceCollection services, IWebHostEnvironment env, IConfiguration configuration)
        {
            base.ConfigureServicesPre(services, env, configuration);

            //string pathToKey = Path.Combine(Directory.GetCurrentDirectory(), "keys", "firebase_admin_sdk.json");
            FirebaseApp.Create(new AppOptions
            {
                //Credential = GoogleCredential.FromFile(pathToKey)
                Credential = GoogleCredential.GetApplicationDefault()
            });

            services.AddMemoryCache();
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
            services.AddSingleton<Services.Authorization.IAuthorizationService, TAuthorizationService>();

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
            options.AddPolicy(ConfigurationSectionKey,
                builder =>
                {
                    builder.AuthenticationSchemes.Add(FirebaseAuthenticationOptions.AuthenticationScheme);
                    builder.RequireAuthenticatedUser();
                });
        }

        protected virtual void AuthorizationOptionsDefaultPolicy(AuthorizationOptions options)
        {
            options.DefaultPolicy = options.GetPolicy(ConfigurationSectionKey);
        }
        #endregion

        #region Protected Properties
        protected override string ConfigurationSectionKey => "Firebase";
        #endregion
    }
}
