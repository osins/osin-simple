package validate

import (
	"fmt"
	"strings"

	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/model/face"
	"github.com/osins/osin-simple/simple/request"
	"github.com/osins/osin-simple/simple/response"
	"github.com/osins/osin-simple/simple/util"
)

type AccessRequestValidate struct {
	Conf      *config.SimpleConfig
	Req       *request.AccessRequest
	Res       *response.AccessResponse
	Authorize face.Authorize
	Access    face.Access
	Client    face.Client
	User      face.User
}

func (val *AccessRequestValidate) Validate() error {
	if len(val.Req.Code) == 0 {
		return fmt.Errorf("code is null.")
	}

	if !val.Conf.AllowAccessGrantType.Exists(val.Req.GrantType) {
		return fmt.Errorf("unknown grant type")
	}

	switch val.Req.GrantType {
	case request.ACCESS_GRANT_AUTHORIZATION_CODE:
		if err := val.authorizeValidate(); err != nil {
			return err
		}

		return nil
	case request.ACCESS_GRANT_REFRESH_TOKEN:
		if err := val.refreshTokenValidate(); err != nil {
			val.Conf.Logger.Error("refresh token update error: %s", err)
			return err
		}

		return nil
	case request.ACCESS_GRANT_PASSWORD:
		if err := val.passwordValidate(); err != nil {
			val.Conf.Logger.Error("access password validate error: %s", err)
			return err
		}

		return nil
		// case CLIENT_CREDENTIALS:
		// 	return s.handleClientCredentialsRequest(w, r)
		// case ASSERTION:
		// 	return s.handleAssertionRequest(w, r)
	}

	return nil
}

func (val *AccessRequestValidate) authorizeValidate() (err error) {
	val.Authorize, err = val.Conf.Storage.Authorize.Get(val.Req.Code)
	if err != nil {
		val.Conf.Logger.Error("authorize storage get by code: %s, error: %v", val.Req.Code, val)
		return err
	}

	if val.Authorize == nil {
		return fmt.Errorf("authorization data is nil")
	}

	if val.Authorize.IsExpiredAt(val.Conf.Now()) {
		return fmt.Errorf("authorization data is expired")
	}

	if len(val.Authorize.GetClient().GetId()) == 0 {
		return fmt.Errorf("authorization client id is nil")
	}

	if len(val.Authorize.GetClient().GetSecret()) == 0 {
		return fmt.Errorf("authorization secret is nil")
	}

	if len(val.Authorize.GetClient().GetRedirectUri()) == 0 {
		return fmt.Errorf("client redirect uri is error")
	}

	val.Client = val.Authorize.GetClient()
	val.User = val.Authorize.GetUser()

	return nil
}

func (val *AccessRequestValidate) refreshTokenValidate() (err error) {
	// "refresh_token" is required
	if val.Req.Code == "" {
		return fmt.Errorf("refresh_token is required")
	}

	// must be a valid refresh code
	val.Access, err = val.Conf.Storage.Access.GetByRefreshToken(val.Req.Code)
	if err != nil {
		val.Conf.Logger.Error("access storage get by refresh token error: %s", err)
		return fmt.Errorf("error loading access data by refresh code.")
	}

	if val.Access == nil {
		return fmt.Errorf("access data is nil")
	}

	val.Conf.Logger.Info("refresh token validate, client id: %s, client: %v", val.Req.ClientId, val.Access.GetClient())

	// client must be the same as the previous token
	if len(val.Access.GetClient().GetId()) == 0 || val.Access.GetClient().GetId() != val.Req.ClientId {
		return fmt.Errorf("Client id must be the same from previous token")
	}

	val.Client = val.Access.GetClient()
	val.User = val.Access.GetUser()

	if val.extraScopes(val.Access.GetScope(), val.Req.Scope) {
		return fmt.Errorf("the requested scope must not include any scope not originally granted by the resource owner")
	}

	return nil
}

func (val *AccessRequestValidate) passwordValidate() (err error) {
	// "username" and "password" is required
	if val.Req.Username == "" || val.Req.Password == "" {
		return fmt.Errorf("username and pass required")
	}

	if val.Conf.Storage.User == nil {
		return fmt.Errorf("user storage not bind.")
	}

	val.User, err = val.Conf.Storage.User.GetByPassword(val.Req.Username, val.Req.Password)
	if err != nil {
		return err
	}

	val.Client, err = val.Conf.Storage.Client.Get(val.Req.ClientId)
	if err != nil {
		return err
	}

	return nil
}

func (val *AccessRequestValidate) extraScopes(access_scopes, refresh_scopes string) bool {
	access_scopes_list := strings.Split(access_scopes, " ")
	refresh_scopes_list := strings.Split(refresh_scopes, " ")

	access_map := make(map[string]int)

	for _, scope := range access_scopes_list {
		if scope == "" {
			continue
		}
		access_map[scope] = 1
	}

	for _, scope := range refresh_scopes_list {
		if scope == "" {
			continue
		}
		if _, ok := access_map[scope]; !ok {
			return true
		}
	}
	return false
}

func (val *AccessRequestValidate) CodeChallengeValidate() error {
	if !val.Conf.RequirePKCEForPublicClients {
		return nil
	}

	// Verify PKCE, if present in the authorization data
	if len(val.Req.CodeVerifier) == 0 {
		return fmt.Errorf("code verifier not exists.")
	}

	if len(val.Req.CodeVerifier) == 0 {
		return fmt.Errorf("code challenge string is null.")
	}

	// https://tools.ietf.org/html/rfc7636#section-4.1
	challenge, err := util.NewCodeVerifier(val.Req.CodeVerifier).CodeChallenge(util.PKCEType(val.Req.CodeVerifierMethod))
	if err != nil {
		return err
	}

	if challenge != val.Authorize.GetCodeChallenge() {
		return fmt.Errorf("code challenge string error.")
	}

	return nil
}
