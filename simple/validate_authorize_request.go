package simple

import (
	"fmt"
	"net/url"

	"github.com/openshift/osin"
)

type authorizeRequestValidate struct {
	server *SimpleServer
	req    *osin.AuthorizeRequest
}

func (val *authorizeRequestValidate) Validate() error {
	var err error

	// create the authorization request
	val.req.RedirectUri, err = url.QueryUnescape(val.req.RedirectUri)
	if err != nil {
		return fmt.Errorf("request redirect uri error.")
	}

	val.req.Authorized = false

	if val.req.Client == nil {
		return fmt.Errorf("client is null.")
	}

	// must have a valid client
	var client osin.Client
	client, err = val.server.Storage.GetClient(val.req.Client.GetId())
	if err != nil {
		return err
	}

	if client == nil {
		return fmt.Errorf("storage client is null.")
	}

	if client.GetRedirectUri() == "" {
		return fmt.Errorf("server client redirect uri is null.")
	}

	if client.GetSecret() != val.req.Client.GetSecret() {
		return fmt.Errorf("client secret error.")
	}

	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if val.req.RedirectUri == "" && osin.FirstUri(val.req.RedirectUri, val.server.Config.RedirectUriSeparator) == client.GetRedirectUri() {
		val.req.RedirectUri = osin.FirstUri(val.req.RedirectUri, val.server.Config.RedirectUriSeparator)
	}

	if realRedirectUri, err := osin.ValidateUriList(client.GetRedirectUri(), val.req.RedirectUri, val.server.Config.RedirectUriSeparator); err != nil {
		return fmt.Errorf("redirect validate uri list error.")
	} else {
		val.req.RedirectUri = realRedirectUri
	}

	if !val.server.Config.AllowedAuthorizeTypes.Exists(val.req.Type) {
		return fmt.Errorf(osin.E_UNSUPPORTED_RESPONSE_TYPE)
	}

	switch val.req.Type {
	case osin.CODE:
		val.req.Expiration = val.server.Config.AuthorizationExpiration
		return val.codeChallenge()
	case osin.TOKEN:
		val.req.Expiration = val.server.Config.AccessExpiration
	}

	return nil
}

func (val *authorizeRequestValidate) codeChallenge() error {
	// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
	if len(val.req.CodeChallenge) == 0 {
		if !val.server.Config.RequirePKCEForPublicClients {
			return nil
		}

		return fmt.Errorf("client code challenge secret error.")
	}

	// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
	if len(val.req.CodeChallengeMethod) == 0 {
		val.req.CodeChallengeMethod = osin.PKCE_PLAIN
	}

	if val.req.CodeChallengeMethod != osin.PKCE_PLAIN && val.req.CodeChallengeMethod != osin.PKCE_S256 {
		return fmt.Errorf("code challenge method validate error.")
	}

	// https://tools.ietf.org/html/rfc7636#section-4.2
	if matched := pkceMatcher.MatchString(val.req.CodeChallenge); !matched {
		return fmt.Errorf("code challenge matcher validate error.")
	}

	return nil
}
