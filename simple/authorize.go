package simple

import (
	"fmt"
	"net/url"

	"github.com/openshift/osin"
)

func NewAuthorize(s *SimpleServer) Authorize {
	return &authorize{
		Server: s,
	}
}

type Authorize interface {
	Authorization(req *osin.AuthorizeRequest) (*osin.AuthorizeData, error)
}

type authorize struct {
	Server *SimpleServer
}

func (s *authorize) Authorization(req *osin.AuthorizeRequest) (*osin.AuthorizeData, error) {
	if err := s.validate(req); err != nil {
		return nil, err
	}

	fmt.Printf("finish authorize request.\n")
	// HANDLE LOGIN PAGE HERE
	// ctx.Redirect(ToLoginPage())

	req.Authorized = true
	ad, err := s.genAuthorizeData(req)
	if err != nil {
		return nil, err
	}

	return ad, nil
}

func (s *authorize) validate(req *osin.AuthorizeRequest) error {
	var err error

	// create the authorization request
	req.RedirectUri, err = url.QueryUnescape(req.RedirectUri)
	if err != nil {
		return fmt.Errorf(osin.E_INVALID_REQUEST)
	}

	req.Authorized = false

	// must have a valid client
	var client osin.Client
	client, err = s.Server.Storage.GetClient(req.Client.GetId())
	if err != nil {
		return fmt.Errorf(osin.E_SERVER_ERROR)
	}

	if err == osin.ErrNotFound {
		return fmt.Errorf(osin.E_UNAUTHORIZED_CLIENT)
	}

	if client == nil {
		return fmt.Errorf(osin.E_UNAUTHORIZED_CLIENT)
	}

	if client.GetRedirectUri() == "" {
		return fmt.Errorf(osin.E_UNAUTHORIZED_CLIENT)
	}

	if client.GetSecret() != req.Client.GetSecret() {
		return fmt.Errorf("client secret error.")
	}

	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if req.RedirectUri == "" && osin.FirstUri(req.RedirectUri, s.Server.Config.RedirectUriSeparator) == client.GetRedirectUri() {
		req.RedirectUri = osin.FirstUri(req.RedirectUri, s.Server.Config.RedirectUriSeparator)
	}

	if realRedirectUri, err := osin.ValidateUriList(client.GetRedirectUri(), req.RedirectUri, s.Server.Config.RedirectUriSeparator); err != nil {
		return fmt.Errorf(osin.E_INVALID_REQUEST)
	} else {
		req.RedirectUri = realRedirectUri
	}

	requestType := osin.AuthorizeRequestType(req.Type)
	if s.Server.Config.AllowedAuthorizeTypes.Exists(requestType) {
		switch requestType {
		case osin.CODE:
			req.Expiration = s.Server.Config.AuthorizationExpiration

			// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
			if len(req.CodeChallenge) == 0 {
				if s.Server.Config.RequirePKCEForPublicClients && osin.CheckClientSecret(req.Client, "") {
					return fmt.Errorf(osin.E_INVALID_REQUEST)
				}
			} else {
				// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
				if len(req.CodeChallengeMethod) == 0 {
					req.CodeChallengeMethod = osin.PKCE_PLAIN
				}
				if req.CodeChallengeMethod != osin.PKCE_PLAIN && req.CodeChallengeMethod != osin.PKCE_S256 {
					return fmt.Errorf(osin.E_INVALID_REQUEST)
				}

				// https://tools.ietf.org/html/rfc7636#section-4.2
				if matched := pkceMatcher.MatchString(req.CodeChallenge); !matched {
					return fmt.Errorf(osin.E_INVALID_REQUEST)
				}
			}

		case osin.TOKEN:
			req.Expiration = s.Server.Config.AccessExpiration
		}

		return nil
	}

	return fmt.Errorf(osin.E_UNSUPPORTED_RESPONSE_TYPE)
}

func (s *authorize) genAuthorizeData(ar *osin.AuthorizeRequest) (*osin.AuthorizeData, error) {
	if !ar.Authorized {
		return nil, fmt.Errorf("authorized is false.")
	}

	if ar.Type == osin.TOKEN {
		// generate token directly
		ret := &osin.AccessRequest{
			Type:            osin.IMPLICIT,
			Code:            "",
			Client:          ar.Client,
			RedirectUri:     ar.RedirectUri,
			Scope:           ar.Scope,
			GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
			Authorized:      true,
			Expiration:      ar.Expiration,
			UserData:        ar.UserData,
		}

		NewSimpleAccess(s.Server).GenAccessData(ret)

		return &osin.AuthorizeData{
			Code:                ret.Code,
			Client:              ar.Client,
			RedirectUri:         ar.RedirectUri,
			Scope:               ar.Scope,
			ExpiresIn:           ar.Expiration,
			UserData:            ar.UserData,
			State:               ar.State,
			CodeChallenge:       ar.CodeChallenge,
			CodeChallengeMethod: ar.CodeChallengeMethod,
		}, nil
	}

	// generate authorization token
	ret := &osin.AuthorizeData{
		Client:      ar.Client,
		CreatedAt:   s.Server.Now(),
		ExpiresIn:   ar.Expiration,
		RedirectUri: ar.RedirectUri,
		State:       ar.State,
		Scope:       ar.Scope,
		UserData:    ar.UserData,
		// Optional PKCE challenge
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
	}

	// generate token code
	code, err := s.Server.AuthorizeTokenGen.GenerateAuthorizeToken(ret)
	if err != nil {
		return nil, fmt.Errorf(osin.E_SERVER_ERROR)
	}

	ret.Code = code

	// save authorization token
	if err = s.Server.Storage.SaveAuthorize(ret); err != nil {
		return nil, fmt.Errorf(osin.E_SERVER_ERROR)
	}

	return ret, nil
}
