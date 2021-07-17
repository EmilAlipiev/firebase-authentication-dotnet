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
        /// <param name="bundleIdentifier">required for Ios as X-Ios-Bundle-Identifier header if Api key is restricted by Bundle identifier</param>
        public FirebaseConfig(string apiKey, string bundleIdentifier = null)
        {
            this.ApiKey = apiKey;
            BundleIdentifier = bundleIdentifier;
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
        public string BundleIdentifier { get; set; }
    }
}
