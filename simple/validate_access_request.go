package simple

import (
	"fmt"
	"strings"

	"github.com/openshift/osin"
)

type accessRequestValidate struct {
	server *SimpleServer
	req    *osin.AccessRequest
	userId string
}

func (val *accessRequestValidate) Validate() error {
	if len(val.req.Code) == 0 {
		return fmt.Errorf("code is null.")
	}

	if !val.server.Config.AllowedAccessTypes.Exists(val.req.Type) {
		return fmt.Errorf("unknown grant type")
	}

	switch val.req.Type {
	case osin.AUTHORIZATION_CODE:
		if err := val.authorizeValidate(); err != nil {
			return err
		}
	case osin.REFRESH_TOKEN:
		if err := val.refreshTokenValidate(); err != nil {
			return err
		}
	case osin.PASSWORD:
		if err := val.authorizeValidate(); err != nil {
			return err
		}
		if err := val.passwordValidate(); err != nil {
			return err
		}
		// case CLIENT_CREDENTIALS:
		// 	return s.handleClientCredentialsRequest(w, r)
		// case ASSERTION:
		// 	return s.handleAssertionRequest(w, r)
	}

	return nil
}

func (val *accessRequestValidate) authorizeValidate() error {
	ad, err := val.server.Storage.LoadAuthorize(val.req.Code)
	if err != nil {
		return err
	}

	if ad == nil {
		return fmt.Errorf("authorization data is nil")
	}

	if ad.Client == nil {
		return fmt.Errorf("authorization client is nil")
	}

	if ad.Client.GetRedirectUri() != val.req.RedirectUri {
		return fmt.Errorf("client redirect uri is error")
	}

	if client, err := val.server.Storage.GetClient(val.req.Client.GetId()); err != nil || client == nil || client.GetId() != val.req.Client.GetId() {
		return fmt.Errorf("client is error.")
	}

	if ad.IsExpiredAt(val.server.Now()) {
		return fmt.Errorf("authorization data is expired")
	}

	val.req.AuthorizeData = ad

	return nil
}

func (val *accessRequestValidate) refreshTokenValidate() error {
	// "refresh_token" is required
	if val.req.Code == "" {
		return fmt.Errorf("refresh_token is required")
	}

	// must have a valid client
	client, err := val.server.Storage.GetClient(val.req.Client.GetId())
	if err != nil || client == nil || client.GetId() != val.req.Client.GetId() {
		return fmt.Errorf("client valid faild.")
	}

	// must be a valid refresh code
	fmt.Printf("\nrefresh code: %s\n", val.req.Code)
	val.req.AccessData, err = val.server.Storage.LoadRefresh(val.req.Code)
	if err != nil {
		return fmt.Errorf("error loading access data by refresh code.")
	}

	if val.req.AccessData == nil {
		return fmt.Errorf("access data is nil")
	}

	if val.req.AccessData.Client.GetRedirectUri() == "" {
		return fmt.Errorf("access data client redirect uri is empty")
	}

	// client must be the same as the previous token
	if val.req.AccessData.Client.GetId() != val.req.Client.GetId() {
		return fmt.Errorf("Client id must be the same from previous token")
	}

	// set rest of data
	val.req.RedirectUri = val.req.AccessData.Client.GetRedirectUri()
	val.req.UserData = val.req.AccessData.UserData
	if val.req.Scope == "" {
		val.req.Scope = val.req.AccessData.Scope
	}

	if val.extraScopes(val.req.AccessData.Scope, val.req.Scope) {
		return fmt.Errorf("the requested scope must not include any scope not originally granted by the resource owner")
	}

	return nil
}

func (val *accessRequestValidate) passwordValidate() error {
	// "username" and "password" is required
	if val.req.Username == "" || val.req.Password == "" {
		return fmt.Errorf("username and pass required")
	}

	if val.server.UserStorage == nil {
		return nil
	}

	var err error
	val.userId, err = val.server.UserStorage.GetId(val.req.Username, val.req.Password)

	return err
}

func (s *accessRequestValidate) extraScopes(access_scopes, refresh_scopes string) bool {
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
