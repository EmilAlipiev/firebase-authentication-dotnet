namespace Firebase.Auth
{
    /// <summary>
    /// The auth config. 
    /// </summary>
    public class FirebaseConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FirebaseConfig"/> class.
        /// </summary>
        /// <param name="apiKey"> The api key of your Firebase app. </param>
        /// <param name="IosbundleIdentifier">required for Ios as X-Ios-Bundle-Identifier header if Api key is restricted by Bundle identifier</param>
        public FirebaseConfig(string apiKey, string IosbundleIdentifier = null)
        {
            this.ApiKey = apiKey;
            IosBundleIdentifier = IosbundleIdentifier;
        }

        /// <summary>
        /// Gets or sets the api key of your Firebase app. 
        /// </summary>
        public string ApiKey
        {
            get;
            set;
        }

        /// <summary>
        /// Required for Ios as X-Ios-Bundle-Identifier header if Api key is restricted by Bundle identifie
        /// </summary>
        public string IosBundleIdentifier { get; set; }
    }
}
