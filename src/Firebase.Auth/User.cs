namespace Firebase.Auth
{
    using System.ComponentModel;

    using Newtonsoft.Json;

    /// <summary>
    /// Basic information about the logged in user.
    /// </summary>
    public class User
    {
        /// <summary>
        /// The uid of the authenticated user.
        /// </summary>
        [JsonProperty("localId", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public string LocalId
        {
            get;
            set;
        }

        /// <summary>
        /// The linked provider ID (e.g. "google.com" for the Google provider).
        /// </summary>
        [JsonProperty("providerId", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public string ProviderId
        {
            get;
            set;
        }

        /// <summary>
        /// The unique ID identifies the IdP account.
        /// </summary>
        [JsonProperty("federatedId", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public string FederatedId
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the first name.
        /// </summary>
        [JsonProperty("firstName", DefaultValueHandling = DefaultValueHandling.Populate)] 
        [DefaultValue("")]
        public string FirstName
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the last name.
        /// </summary>
        [JsonProperty("lastName", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public string LastName
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the display name.
        /// </summary>
        [JsonProperty("displayName", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public string DisplayName
        {
            get;
            set;
        }

        /// <summary>
        /// The email of the account.
        /// </summary>
        [JsonProperty("email", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public string Email
        {
            get;
            set;
        }

        /// <summary>
        /// Whether the sign-in email is verified.
        /// </summary>
        [JsonProperty("emailVerified", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue(false)]
        public bool IsEmailVerified
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the photo url.
        /// </summary>
        [JsonProperty("photoUrl", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public string PhotoUrl
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the phone number.
        /// </summary>
        [JsonProperty("phoneNumber", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public string PhoneNumber
        {
            get;
            set;
        }
    }
}
