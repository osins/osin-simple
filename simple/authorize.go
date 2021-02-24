package simple

import (
	"fmt"

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
	fmt.Printf("start authorize validate:")
	if err := s.requestValidate(req).Validate(); err != nil {
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

func (s *authorize) requestValidate(req *osin.AuthorizeRequest) ValidateRequest {
	return &authorizeRequestValidate{
		server: s.Server,
		req:    req,
	}
}

func (s *authorize) genAuthorizeData(req *osin.AuthorizeRequest) (*osin.AuthorizeData, error) {
	if !req.Authorized {
		return nil, fmt.Errorf("authorized is false.")
	}

	if req.Type == osin.TOKEN {
		return s.tokenType(req)
	}

	return s.otherType(req)
}

func (s *authorize) tokenType(ar *osin.AuthorizeRequest) (*osin.AuthorizeData, error) {
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

	NewAccess(s.Server).GenAccessData(ret)

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

func (s *authorize) otherType(ar *osin.AuthorizeRequest) (*osin.AuthorizeData, error) {
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
