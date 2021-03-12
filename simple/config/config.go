package config

import (
	"time"

	"github.com/osins/osin-simple/simple/log"
	"github.com/osins/osin-simple/simple/model/face"
	"github.com/osins/osin-simple/simple/request"
	"github.com/osins/osin-simple/simple/storage"
)

func NewServerConfig() *SimpleConfig {
	return &SimpleConfig{
		AuthorizationExpiration: 250,
		AccessExpiration:        3600,
		TokenType:               "Bearer",
		AllowedAuthorizeTypes: request.AllowedAuthorizeResponseType{
			request.AUTHORIZE_RESPONSE_CODE,
			request.AUTHORIZE_RESPONSE_TOKEN,
		},
		AllowAccessGrantType: request.AllowedAccessGrantType{
			request.ACCESS_GRANT_AUTHORIZATION_CODE,
			request.ACCESS_GRANT_REFRESH_TOKEN,
		},
		ErrorStatusCode:           200,
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
		RetainTokenAfterRefresh:   false,
		Now: func() time.Time {
			return time.Now()
		},
	}
}

type SimpleConfig struct {
	Storage struct {
		Client    storage.ClientStorage
		User      storage.UserStorage
		Access    storage.AccessStorage
		Authorize storage.AuthorizeStorage
	}
	AuthorizeCode face.AuthorizeCode
	AccessToken   face.AccessToken
	Logger        log.Logger
	Now           func() time.Time

	// Authorization token expiration in seconds (default 5 minutes)
	AuthorizationExpiration int32

	// Access token expiration in seconds (default 1 hour)
	AccessExpiration int32

	// Token type to return
	TokenType string

	// List of allowed authorize types (only CODE by default)
	AllowedAuthorizeTypes request.AllowedAuthorizeResponseType

	// List of allowed access types (only AUTHORIZATION_CODE by default)
	AllowAccessGrantType request.AllowedAccessGrantType

	// HTTP status code to return for errors - default 200
	// Only used if response was created from server
	ErrorStatusCode int

	// If true allows client secret also in params, else only in
	// Authorization header - default false
	AllowClientSecretInParams bool

	// If true allows access request using GET, else only POST - default false
	AllowGetAccessRequest bool

	// Require PKCE for code flows for public OAuth clients - default false
	RequirePKCEForPublicClients bool

	// Separator to support multiple URIs in Client.GetRedirectUri().
	// If blank (the default), don't allow multiple URIs.
	RedirectUriSeparator string

	// RetainTokenAfter Refresh allows the server to retain the access and
	// refresh token for re-use - default false
	RetainTokenAfterRefresh bool
}
