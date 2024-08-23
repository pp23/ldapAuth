package ldapIdp

// Config the plugin configuration.
type Config struct {
	Enabled                    bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	LogLevel                   string   `json:"logLevel,omitempty" yaml:"logLevel,omitempty"`
	URL                        string   `json:"url,omitempty" yaml:"url,omitempty"`
	Port                       uint16   `json:"port,omitempty" yaml:"port,omitempty"`
	CacheTimeout               uint32   `json:"cacheTimeout,omitempty" yaml:"cacheTimeout,omitempty"`
	CacheCookieName            string   `json:"cacheCookieName,omitempty" yaml:"cacheCookieName,omitempty"`
	CacheCookiePath            string   `json:"cacheCookiePath,omitempty" yaml:"cacheCookiePath,omitempty"`
	CacheCookieSecure          bool     `json:"cacheCookieSecure,omitempty" yaml:"cacheCookieSecure,omitempty"`
	CacheKey                   string   `json:"cacheKey,omitempty" yaml:"cacheKey,omitempty"`
	StartTLS                   bool     `json:"startTls,omitempty" yaml:"startTls,omitempty"`
	InsecureSkipVerify         bool     `json:"insecureSkipVerify,omitempty" yaml:"insecureSkipVerify,omitempty"`
	MinVersionTLS              string   `json:"minVersionTls,omitempty" yaml:"minVersionTls,omitempty"`
	MaxVersionTLS              string   `json:"maxVersionTls,omitempty" yaml:"maxVersionTls,omitempty"`
	CertificateAuthority       string   `json:"certificateAuthority,omitempty" yaml:"certificateAuthority,omitempty"`
	Attribute                  string   `json:"attribute,omitempty" yaml:"attribute,omitempty"`
	SearchFilter               string   `json:"searchFilter,omitempty" yaml:"searchFilter,omitempty"`
	BaseDN                     string   `json:"baseDn,omitempty" yaml:"baseDn,omitempty"`
	BindDN                     string   `json:"bindDn,omitempty" yaml:"bindDn,omitempty"`
	BindPassword               string   `json:"bindPassword,omitempty" yaml:"bindPassword,omitempty"`
	ForwardUsername            bool     `json:"forwardUsername,omitempty" yaml:"forwardUsername,omitempty"`
	ForwardUsernameHeader      string   `json:"forwardUsernameHeader,omitempty" yaml:"forwardUsernameHeader,omitempty"`
	ForwardAuthorization       bool     `json:"forwardAuthorization,omitempty" yaml:"forwardAuthorization,omitempty"`
	ForwardExtraLdapHeaders    bool     `json:"forwardExtraLdapHeaders,omitempty" yaml:"forwardExtraLdapHeaders,omitempty"`
	WWWAuthenticateHeader      bool     `json:"wwwAuthenticateHeader,omitempty" yaml:"wwwAuthenticateHeader,omitempty"`
	WWWAuthenticateHeaderRealm string   `json:"wwwAuthenticateHeaderRealm,omitempty" yaml:"wwwAuthenticateHeaderRealm,omitempty"`
	EnableNestedGroupFilter    bool     `json:"enableNestedGroupsFilter,omitempty" yaml:"enableNestedGroupsFilter,omitempty"`
	AllowedGroups              []string `json:"allowedGroups,omitempty" yaml:"allowedGroups,omitempty"`
	AllowedUsers               []string `json:"allowedUsers,omitempty" yaml:"allowedUsers,omitempty"`
	Username                   string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                    true,
		LogLevel:                   "INFO",
		URL:                        "",  // Supports: ldap://, ldaps://
		Port:                       389, // Usually 389 or 636
		CacheTimeout:               300, // In seconds, default to 5m
		CacheCookieName:            "ldapAuth_session_token",
		CacheCookiePath:            "",
		CacheCookieSecure:          false,
		CacheKey:                   "super-secret-key",
		StartTLS:                   false,
		InsecureSkipVerify:         false,
		MinVersionTLS:              "tls.VersionTLS12",
		MaxVersionTLS:              "tls.VersionTLS13",
		CertificateAuthority:       "",
		Attribute:                  "cn", // Usually uid or sAMAccountname
		SearchFilter:               "",
		BaseDN:                     "",
		BindDN:                     "",
		BindPassword:               "",
		ForwardUsername:            true,
		ForwardUsernameHeader:      "Username",
		ForwardAuthorization:       false,
		ForwardExtraLdapHeaders:    false,
		WWWAuthenticateHeader:      true,
		WWWAuthenticateHeaderRealm: "",
		EnableNestedGroupFilter:    false,
		AllowedGroups:              nil,
		AllowedUsers:               nil,
		Username:                   "",
	}
}
