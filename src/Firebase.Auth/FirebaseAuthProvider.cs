namespace Firebase.Auth
{
    using System;
    using System.Diagnostics;
    using System.Linq;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// The auth token provider.
    /// </summary>
    public class FirebaseAuthProvider : IDisposable, IFirebaseAuthProvider
    {
        private const string GoogleRefreshAuth = "https://securetoken.googleapis.com/v1/token?key={0}";
        private const string GoogleCustomAuthUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key={0}";
        private const string GoogleGetUser = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key={0}";
        private const string GoogleIdentityUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyAssertion?key={0}";
        private const string GoogleSignUpUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={0}";
        private const string GooglePasswordUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={0}";
        private const string GoogleDeleteUserUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/deleteAccount?key={0}";
        private const string GoogleGetConfirmationCodeUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key={0}";
        private const string GoogleSetAccountUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/setAccountInfo?key={0}";
        private const string GoogleCreateAuthUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/createAuthUri?key={0}";

        private const string ProfileDeleteDisplayName = "DISPLAY_NAME";
        private const string ProfileDeletePhotoUrl = "PHOTO_URL";

        private readonly FirebaseConfig authConfig;
        private readonly HttpClient client;

        /// <summary>
        /// Initializes a new instance of the <see cref="FirebaseAuthProvider"/> class.
        /// </summary>
        /// <param name="authConfig"> The auth config. </param>
        public FirebaseAuthProvider(FirebaseConfig authConfig)
        {
            this.authConfig = authConfig;
            client = new HttpClient();
        }

        /// <summary>
        /// Sign in with a custom token. You would usually create and sign such a token on your server to integrate with your existing authentiocation system.
        /// </summary>
        /// <param name="customToken"> The access token retrieved from login provider of your choice. </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInWithCustomTokenAsync(string customToken)
        {
            string content = $"{{\"token\":\"{customToken}\",\"returnSecureToken\":true}}";
            FirebaseAuthLink firebaseAuthLink = await ExecuteWithPostContentAsync(GoogleCustomAuthUrl, content).ConfigureAwait(false);
            firebaseAuthLink.User = await GetUserAsync(firebaseAuthLink.FirebaseToken).ConfigureAwait(false);
            return firebaseAuthLink;
        }

        /// <summary>
        /// Using the idToken of an authenticated user, get the details of the user's account
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <returns> The <see cref="User"/>. </returns>
        public async Task<User> GetUserAsync(string firebaseToken)
        {
            string content = $"{{\"idToken\":\"{firebaseToken}\"}}";
            HttpResponseMessage response = await client.PostAsync(new Uri(string.Format(GoogleGetUser, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);

            JObject resultJson = JObject.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false));
            User user = JsonConvert.DeserializeObject<User>(resultJson["users"].First().ToString());
            return user;
        }

        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="auth"> The authenticated user to verify email address. </param>
        public async Task<User> GetUserAsync(FirebaseAuth auth)
        {
            return await GetUserAsync(auth.FirebaseToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Using the provided access token from third party auth provider (google, facebook...), get the firebase auth with token and basic user credentials.
        /// </summary>
        /// <param name="authType"> The auth type. </param>
        /// <param name="oauthAccessToken"> The access token retrieved from login provider of your choice. </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInWithOAuthAsync(FirebaseAuthType authType, string oauthAccessToken)
        {
            string providerId = GetProviderId(authType);
            string content = $"{{\"postBody\":\"access_token={oauthAccessToken}&providerId={providerId}\",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleIdentityUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Using the provided Id token from google signin, get the firebase auth with token and basic user credentials.
        /// </summary>
        /// <param name="authType"> The auth type. </param>
        /// <param name="IdToken"> The Id token retrieved from google signin </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInWithIdTokenAsync(string IdToken)
        {
            string providerId = GetProviderId(FirebaseAuthType.Google);
            string content = $"{{\"postBody\":\"id_token={IdToken}&providerId={providerId}\",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleIdentityUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Sign in user anonymously. He would still have a user id and access token generated, but name and other personal user properties will be null.
        /// </summary>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInAnonymouslyAsync()
        {
            string content = $"{{\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleSignUpUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Using the provided email and password, get the firebase auth with token and basic user credentials.
        /// </summary>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInWithEmailAndPasswordAsync(string email, string password)
        {
            string content = $"{{\"email\":\"{email}\",\"password\":\"{password}\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GooglePasswordUrl, content).ConfigureAwait(false);
        }


        /// <summary>
        /// Creates new user with given credentials.
        /// </summary>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <param name="displayName"> Optional display name. </param>
        /// <param name="sendVerificationEmail"> Optional. Whether to send user a link to verfiy his email address. </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> CreateUserWithEmailAndPasswordAsync(string email, string password, string displayName = "", bool sendVerificationEmail = false, string locale = null)
        {
            string content = $"{{\"email\":\"{email}\",\"password\":\"{password}\",\"returnSecureToken\":true}}";

            FirebaseAuthLink signup = await ExecuteWithPostContentAsync(GoogleSignUpUrl, content).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(displayName))
            {
                // set display name
                content = $"{{\"displayName\":\"{displayName}\",\"idToken\":\"{signup.FirebaseToken}\",\"returnSecureToken\":true}}";

                await ExecuteWithPostContentAsync(GoogleSetAccountUrl, content).ConfigureAwait(false);

                signup.User.DisplayName = displayName;
            }

            if (sendVerificationEmail)
            {
                //send verification email
                await SendEmailVerificationAsync(signup).ConfigureAwait(false);
            }

            return signup;
        }

        /// <summary>
        /// Updates profile (displayName and photoUrl) of user tied to given user token.
        /// </summary>
        /// <param name="displayName"> The new display name. </param>
        /// <param name="photoUrl"> The new photo URL. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> UpdateProfileAsync(string firebaseToken, string displayName, string photoUrl)
        {
            StringBuilder sb = new StringBuilder($"{{\"idToken\":\"{firebaseToken}\"");
            if (!string.IsNullOrWhiteSpace(displayName) && !string.IsNullOrWhiteSpace(photoUrl))
            {
                sb.Append($",\"displayName\":\"{displayName}\",\"photoUrl\":\"{photoUrl}\"");
            }
            else if (!string.IsNullOrWhiteSpace(displayName))
            {
                sb.Append($",\"displayName\":\"{displayName}\"");
                sb.Append($",\"deleteAttribute\":[\"{ProfileDeletePhotoUrl}\"]");
            }
            else if (!string.IsNullOrWhiteSpace(photoUrl))
            {
                sb.Append($",\"photoUrl\":\"{photoUrl}\"");
                sb.Append($",\"deleteAttribute\":[\"{ProfileDeleteDisplayName}\"]");
            }
            else
            {
                sb.Append($",\"deleteAttribute\":[\"{ProfileDeleteDisplayName}\",\"{ProfileDeletePhotoUrl}\"]");
            }

            sb.Append($",\"returnSecureToken\":true}}");

            return await ExecuteWithPostContentAsync(GoogleSetAccountUrl, sb.ToString()).ConfigureAwait(false);
        }


        /// <summary>
        /// Deletes the user with a recent Firebase Token.
        /// </summary>
        /// <param name="token"> Recent Firebase Token. </param>
        public async Task<bool> DeleteUserAsync(string firebaseToken)
        {
            string content = $"{{ \"idToken\": \"{firebaseToken}\" }}";
            string responseData = "N/A";

            try
            {
                HttpResponseMessage response = await client.PostAsync(new Uri(string.Format(GoogleDeleteUserUrl, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                response.EnsureSuccessStatusCode();
                return response.StatusCode == System.Net.HttpStatusCode.OK;

            }
            catch (Exception ex)
            {
                AuthErrorReason errorReason = GetFailureReason(responseData);
                throw new FirebaseAuthException(GoogleDeleteUserUrl, content, responseData, ex, errorReason);
            }
        }

        /// <summary>
        /// Sends user an email with a link to reset his password.
        /// </summary>
        /// <param name="email"> The email. </param>
        public async Task<bool> SendPasswordResetEmailAsync(string email, string locale = null)
        {
            string responseData = "N/A";
            string content = $"{{\"requestType\":\"PASSWORD_RESET\",\"email\":\"{email}\"}}";
            try
            {

                StringContent StringContent = new StringContent(content, Encoding.UTF8, "application/json");
                if (locale != null)
                {
                    StringContent.Headers.Add("X-Firebase-Locale", locale);
                }

                HttpResponseMessage response = await client.PostAsync(new Uri(string.Format(GoogleGetConfirmationCodeUrl, authConfig.ApiKey)), StringContent).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync();

                response.EnsureSuccessStatusCode();
                return response.StatusCode == System.Net.HttpStatusCode.OK;
            }
            catch (Exception ex)
            {
                AuthErrorReason errorReason = GetFailureReason(responseData);
                throw new FirebaseAuthException(GoogleGetConfirmationCodeUrl, content, responseData, ex, errorReason);

            }
        }

        /// <summary>
        /// You can change a user's password by issuing an HTTP POST request to the Auth setAccountInfo endpoint.
        /// </summary>
        /// <param name="firebaseToken">A Firebase Auth ID token for the user.</param>
        /// <param name="newpassword">User's new password.</param>
        /// <returns></returns>
        public async Task ChangePasswordAsync(string firebaseToken, string newpassword)
        {
            string content = $"{{\"idToken\":\"{firebaseToken}\",\"password\":\"{newpassword}\",\"returnSecureToken\":true}}";

            await ExecuteWithPostContentAsync(GoogleSetAccountUrl, content).ConfigureAwait(false);
        }
        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        public async Task<bool> SendEmailVerificationAsync(string firebaseToken, string locale = null)
        {
            string responseData = "N/A";
            string content = $"{{\"requestType\":\"VERIFY_EMAIL\",\"idToken\":\"{firebaseToken}\"}}";

            try
            {

                StringContent StringContent = new StringContent(content, Encoding.UTF8, "application/json");
                if (locale != null)
                {
                    StringContent.Headers.Add("X-Firebase-Locale", locale);
                }

                HttpResponseMessage response = await client.PostAsync(new Uri(string.Format(GoogleGetConfirmationCodeUrl, authConfig.ApiKey)), StringContent).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync();

                response.EnsureSuccessStatusCode();
                return response.StatusCode == System.Net.HttpStatusCode.OK;
            }
            catch (Exception ex)
            {
                AuthErrorReason errorReason = GetFailureReason(responseData);
                throw new FirebaseAuthException(GoogleGetConfirmationCodeUrl, content, responseData, ex, errorReason);

            }
        }

        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="auth"> The authenticated user to verify email address. </param>
        public async Task<bool> SendEmailVerificationAsync(FirebaseAuth auth, string locale = null)
        {
            return await SendEmailVerificationAsync(auth.FirebaseToken, locale).ConfigureAwait(false);
        }

        /// <summary>
        /// You can update a user's profile (display name / photo URL) by issuing an HTTP POST request to the Auth setAccountInfo endpoint.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <param name="displayName">	User's new display name. </param>
        /// <param name="photoUrl"> User's new photo url. </param>
        /// <param name="deleteAttribute"> List of attributes to delete, "DISPLAY_NAME" or "PHOTO_URL". This will nullify these values.</param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> UpdateUserProfile(string firebaseToken, string displayName, string photoUrl = null, System.Collections.Generic.List<string> deleteAttribute = null)
        {
            string content = $"{{\"idToken\":\"{firebaseToken}\",\"displayName\":\"{displayName}\",\"photoUrl\":\"{photoUrl}\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleSetAccountUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Links the given <see cref="firebaseToken"/> with an email and password. 
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> LinkAccountsAsync(string firebaseToken, string email, string password)
        {
            string content = $"{{\"idToken\":\"{firebaseToken}\",\"email\":\"{email}\",\"password\":\"{password}\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleSetAccountUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Links the authenticated user represented by <see cref="auth"/> with an email and password. 
        /// </summary>
        /// <param name="auth"> The authenticated user to link with specified email and password. </param>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> LinkAccountsAsync(FirebaseAuth auth, string email, string password)
        {
            return await LinkAccountsAsync(auth.FirebaseToken, email, password).ConfigureAwait(false);
        }

        /// <summary>
        /// Links the authenticated user represented by<see cref="firebaseToken"/> with and account from a third party provider.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <param name="authType"> The auth type.  </param>
        /// <param name="oauthAccessToken"> The access token retrieved from login provider of your choice. </param>
        /// <param name="twitterTokenSecret">only when provider is twitter</param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> LinkAccountsAsync(string firebaseToken, FirebaseAuthType authType, string oauthAccessToken, string twitterTokenSecret = null)
        {
            string tokenStr = "access_token";
            string providerId = GetProviderId(authType);
            if (authType == FirebaseAuthType.Google)
            {
                tokenStr = "id_token";
            }
            string content = $"{{\"idToken\":\"{firebaseToken}\",\"postBody\":\"{tokenStr}={oauthAccessToken}&providerId={providerId}\",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true}}";

            if (authType == FirebaseAuthType.Twitter)
            {
                content = $"{{\"idToken\":\"{firebaseToken}\",\"postBody\":\"{tokenStr}={oauthAccessToken}&oauth_token_secret={twitterTokenSecret}&providerId={providerId}\",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true}}";
            }

            return await ExecuteWithPostContentAsync(GoogleIdentityUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Links the authenticated user represented by <see cref="auth"/> with and account from a third party provider.
        /// </summary>
        /// <param name="auth"> The auth. </param>
        /// <param name="authType"> The auth type.  </param>
        /// <param name="oauthAccessToken"> The access token retrieved from login provider of your choice. </param>
        /// <param name="twitterTokenSecret">only when provider is twitter</param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> LinkAccountsAsync(FirebaseAuth auth, FirebaseAuthType authType, string oauthAccessToken, string twitterTokenSecret = null)
        {
            return await LinkAccountsAsync(auth.FirebaseToken, authType, oauthAccessToken, twitterTokenSecret).ConfigureAwait(false);
        }

        /// <summary>
        /// Unlinks the given <see cref="authType"/> from the account associated with <see cref="firebaseToken"/>.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <param name="authType"> The auth type.  </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> UnlinkAccountsAsync(string firebaseToken, FirebaseAuthType authType)
        {
            string providerId = null;
            if (authType == FirebaseAuthType.EmailAndPassword)
            {
                providerId = authType.ToEnumString();
            }
            else
            {
                providerId = GetProviderId(authType);
            }

            string content = $"{{\"idToken\":\"{firebaseToken}\",\"deleteProvider\":[\"{providerId}\"]}}";

            return await ExecuteWithPostContentAsync(GoogleSetAccountUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Unlinks the given <see cref="authType"/> from the authenticated user represented by <see cref="auth"/>.
        /// </summary>
        /// <param name="auth"> The auth. </param>
        /// <param name="authType"> The auth type.  </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> UnlinkAccountsAsync(FirebaseAuth auth, FirebaseAuthType authType)
        {
            return await UnlinkAccountsAsync(auth.FirebaseToken, authType).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets a list of accounts linked to given email.
        /// </summary>
        /// <param name="email"> Email address. </param>
        /// <returns> The <see cref="ProviderQueryResult"/></returns>
        public async Task<ProviderQueryResult> GetLinkedAccountsAsync(string email)
        {
            string content = $"{{\"identifier\":\"{email}\", \"continueUri\": \"http://localhost\"}}";
            string responseData = "N/A";

            try
            {
                HttpResponseMessage response = await client.PostAsync(new Uri(string.Format(GoogleCreateAuthUrl, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                response.EnsureSuccessStatusCode();

                ProviderQueryResult data = JsonConvert.DeserializeObject<ProviderQueryResult>(responseData);
                data.Email = email;

                return data;
            }
            catch (Exception ex)
            {
                throw new FirebaseAuthException(GoogleCreateAuthUrl, content, responseData, ex);
            }
        }

        public async Task<FirebaseAuthLink> RefreshAuthAsync(FirebaseAuth auth)
        {
            string content = $"{{\"grant_type\":\"refresh_token\", \"refresh_token\":\"{auth.RefreshToken}\"}}";
            string responseData = "N/A";

            try
            {
                HttpResponseMessage response = await client.PostAsync(new Uri(string.Format(GoogleRefreshAuth, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);

                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                RefreshAuth refreshAuth = JsonConvert.DeserializeObject<RefreshAuth>(responseData);

                return new FirebaseAuthLink
                {
                    AuthProvider = this,
                    User = auth.User,
                    ExpiresIn = refreshAuth.ExpiresIn,
                    RefreshToken = refreshAuth.RefreshToken,
                    FirebaseToken = refreshAuth.AccessToken
                };
            }
            catch (Exception ex)
            {
                throw new FirebaseAuthException(GoogleRefreshAuth, content, responseData, ex);
            }
        }

        /// <summary>
        /// Disposes all allocated resources. 
        /// </summary>
        public void Dispose()
        {
            client.Dispose();
        }
        /// <summary>
        /// Post request to firebase Api and get response object
        /// </summary>
        /// <param name="googleUrl"></param>
        /// <param name="postContent"></param>
        /// <param name="headername">to be used for locale X-Firebase-Locale</param>
        /// <param name="headervalue">language code: fr</param>
        /// <returns></returns>
        private async Task<FirebaseAuthLink> ExecuteWithPostContentAsync(string googleUrl, string postContent, string locale = null)
        {
            string responseData = "N/A";

            try
            {

                StringContent StringContent = new StringContent(postContent, Encoding.UTF8, "application/json");
                if (locale != null)
                {
                    StringContent.Headers.Add("X-Firebase-Locale", locale);
                }

                HttpResponseMessage response = await client.PostAsync(new Uri(string.Format(googleUrl, authConfig.ApiKey)), StringContent).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                response.EnsureSuccessStatusCode();

                User user = JsonConvert.DeserializeObject<User>(responseData);
                FirebaseAuthLink auth = JsonConvert.DeserializeObject<FirebaseAuthLink>(responseData);

                auth.AuthProvider = this;
                auth.User = user;

                return auth;
            }
            catch (Exception ex)
            {
                AuthErrorReason errorReason = GetFailureReason(responseData);
                throw new FirebaseAuthException(googleUrl, postContent, responseData, ex, errorReason);
            }
        }

        /// <summary>
        /// Resolves failure reason flags based on the returned error code.
        /// </summary>
        /// <remarks>Currently only provides support for failed email auth flags.</remarks>
        private static AuthErrorReason GetFailureReason(string responseData)
        {
            AuthErrorReason failureReason = AuthErrorReason.Undefined;
            try
            {
                if (!string.IsNullOrEmpty(responseData) && responseData != "N/A")
                {
                    //create error data template and try to parse JSON
                    var errorData = new { error = new { code = 0, message = "errorid" } };
                    errorData = JsonConvert.DeserializeAnonymousType(responseData, errorData);

                    //errorData is just null if different JSON was received
                    switch (errorData?.error?.message)
                    {
                        //general errors
                        case "invalid access_token, error code 43.":
                            failureReason = AuthErrorReason.InvalidAccessToken;
                            break;

                        case "CREDENTIAL_TOO_OLD_LOGIN_AGAIN":
                            failureReason = AuthErrorReason.LoginCredentialsTooOld;
                            break;

                        //possible errors from Third Party Authentication using GoogleIdentityUrl
                        case "INVALID_PROVIDER_ID : Provider Id is not supported.":
                            failureReason = AuthErrorReason.InvalidProviderID;
                            break;
                        case "MISSING_REQUEST_URI":
                            failureReason = AuthErrorReason.MissingRequestURI;
                            break;
                        case "A system error has occurred - missing or invalid postBody":
                            failureReason = AuthErrorReason.SystemError;
                            break;

                        //possible errors from Email/Password Account Signup (via signupNewUser or setAccountInfo) or Signin
                        case "INVALID_EMAIL":
                            failureReason = AuthErrorReason.InvalidEmailAddress;
                            break;
                        case "MISSING_PASSWORD":
                            failureReason = AuthErrorReason.MissingPassword;
                            break;

                        //possible errors from Email/Password Account Signup (via signupNewUser or setAccountInfo)
                        case "WEAK_PASSWORD : Password should be at least 6 characters":
                            failureReason = AuthErrorReason.WeakPassword;
                            break;
                        case "EMAIL_EXISTS":
                            failureReason = AuthErrorReason.EmailExists;
                            break;

                        //possible errors from Account Delete
                        case "USER_NOT_FOUND":
                            failureReason = AuthErrorReason.UserNotFound;
                            break;

                        //possible errors from Email/Password Signin
                        case "INVALID_PASSWORD":
                            failureReason = AuthErrorReason.WrongPassword;
                            break;
                        case "EMAIL_NOT_FOUND":
                            failureReason = AuthErrorReason.UnknownEmailAddress;
                            break;
                        case "USER_DISABLED":
                            failureReason = AuthErrorReason.UserDisabled;
                            break;

                        //possible errors from Email/Password Signin or Password Recovery or Email/Password Sign up using setAccountInfo
                        case "MISSING_EMAIL":
                            failureReason = AuthErrorReason.MissingEmail;
                            break;

                        //possible errors from Password Recovery
                        case "MISSING_REQ_TYPE":
                            failureReason = AuthErrorReason.MissingRequestType;
                            break;

                        //possible errors from Account Linking
                        case "INVALID_ID_TOKEN":
                            failureReason = AuthErrorReason.InvalidIDToken;
                            break;

                        //possible errors from Getting Linked Accounts
                        case "INVALID_IDENTIFIER":
                            failureReason = AuthErrorReason.InvalidIdentifier;
                            break;
                        case "MISSING_IDENTIFIER":
                            failureReason = AuthErrorReason.MissingIdentifier;
                            break;
                        case "FEDERATED_USER_ID_ALREADY_LINKED":
                            failureReason = AuthErrorReason.AlreadyLinked;
                            break;
                    }
                }
            }
            catch (JsonReaderException)
            {
                //the response wasn't JSON - no data to be parsed
            }
            catch (Exception e)
            {
                Debug.WriteLine($"Unexpected error trying to parse the response: {e}");
            }

            return failureReason;
        }


        private string GetProviderId(FirebaseAuthType authType)
        {
            switch (authType)
            {
                case FirebaseAuthType.Facebook:
                case FirebaseAuthType.Google:
                case FirebaseAuthType.Github:
                case FirebaseAuthType.Twitter:
                    return authType.ToEnumString();
                case FirebaseAuthType.EmailAndPassword:
                    throw new InvalidOperationException("Email auth type cannot be used like this. Use methods specific to email & password authentication.");
                default:
                    throw new NotImplementedException("");
            }
        }
    }
}