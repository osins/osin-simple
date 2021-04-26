package validate

import (
	"fmt"
	"net/url"

	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/model/face"
	"github.com/osins/osin-simple/simple/request"
	"github.com/osins/osin-simple/simple/response"
	"github.com/osins/osin-simple/simple/util"
)

type AuthorizeRequestValidate struct {
	Conf   *config.SimpleConfig
	Req    *request.AuthorizeRequest
	Res    *response.AuthorizeResponse
	Client face.Client
	User   face.User
}

func (val *AuthorizeRequestValidate) Validate() error {
	var err error

	// create the authorization request
	val.Req.RedirectUri, err = url.QueryUnescape(val.Req.RedirectUri)
	if err != nil {
		return fmt.Errorf("request redirect uri error.")
	}

	if len(val.Req.ClientId) == 0 {
		return fmt.Errorf("client is null: %s", val.Req)
	}

	// must have a valid client
	val.Client, err = val.Conf.Storage.Client.Get(val.Req.ClientId)
	if err != nil {
		return fmt.Errorf("client id not exists, client id: %s", val.Req.ClientId)
	}

	if val.Client == nil {
		return fmt.Errorf("storage client is null.")
	}

	if val.Client.GetRedirectUri() == "" {
		return fmt.Errorf("server client redirect uri is null.")
	}

	// if val.Client.GetSecret() != val.Req.ClientSecret {
	// 	return fmt.Errorf("client secret error.")
	// }

	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if val.Req.RedirectUri == "" && util.FirstUri(val.Req.RedirectUri, val.Conf.RedirectUriSeparator) == val.Client.GetRedirectUri() {
		val.Res.RedirectUri = util.FirstUri(val.Req.RedirectUri, val.Conf.RedirectUriSeparator)
	}

	if realRedirectUri, err := util.ValidateRedirectUriList(val.Client.GetRedirectUri(), val.Req.RedirectUri, val.Conf.RedirectUriSeparator); err != nil {
		return fmt.Errorf("redirect validate uri list error.")
	} else {
		val.Res.RedirectUri = realRedirectUri
	}

	if !val.Conf.AllowedAuthorizeTypes.Exists(val.Req.ResponseType) {
		return fmt.Errorf("unsupported response type: %s", val.Req.ResponseType)
	}

	val.Conf.Logger.Info("authorize response type: %s", val.Req.ResponseType)

	switch val.Req.ResponseType {
	case request.AUTHORIZE_RESPONSE_CODE:
		if err := val.codeChallenge(); err != nil {
			val.Conf.Logger.Error("codeChallenge error: %s", err)
			return err
		}
	case request.AUTHORIZE_RESPONSE_TOKEN:
		if err := val.codeChallenge(); err != nil {
			val.Conf.Logger.Error("codeChallenge error: %s", err)
			return err
		}
	case request.AUTHORIZE_RESPONSE_LOGIN:
		if err := val.codeChallenge(); err != nil {
			val.Conf.Logger.Error("codeChallenge error: %s", err)
			return err
		}

		if len(val.Req.Username) == 0 || len(val.Req.Password) == 0 {
			val.Conf.Logger.Error("username or password is null.")
			return fmt.Errorf("username or password is null.")
		}

		val.User, err = val.Conf.Storage.User.GetByPassword(val.Req.Username, val.Req.Password)
		if err != nil {
			val.Conf.Logger.Error("find user error, username: %s, password: %s, error: %s", val.Req.Username, val.Req.Password, err)
			return err
		}
	}

	val.Res.ExpiresIn = val.Conf.AuthorizationExpiration

	return nil
}

func (val *AuthorizeRequestValidate) codeChallenge() error {
	if !val.Conf.RequirePKCEForPublicClients {
		return nil
	}

	// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
	if len(val.Req.CodeChallenge) == 0 {
		return fmt.Errorf("client code challenge secret error.")
	}

	// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
	if len(val.Req.CodeChallengeMethod) == 0 {
		val.Req.CodeChallengeMethod = string(util.PKCE_PLAIN)
	}

	if val.Req.CodeChallengeMethod != string(util.PKCE_PLAIN) && val.Req.CodeChallengeMethod != string(util.PKCE_S256) {
		return fmt.Errorf("code challenge method validate error.")
	}

	// https://tools.ietf.org/html/rfc7636#section-4.2
	v := util.NewCodeVerifier(val.Req.CodeChallenge)
	if _, err := v.Validate(); err != nil {
		return err
	}

	return nil
}
