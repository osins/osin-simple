package simple

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/model/entity"
	"github.com/osins/osin-simple/simple/request"
	"github.com/osins/osin-simple/simple/response"
	"github.com/osins/osin-simple/simple/validate"
)

func NewAuthorize(s *SimpleServer) Authorize {
	return &authorize{
		Conf: s.Config,
	}
}

type Authorize interface {
	Login(req *request.AuthorizeRequest) (*response.AuthorizeResponse, error)
	Register(req *request.AuthorizeRequest) (res *response.AuthorizeResponse, err error)
	Authorization(req *request.AuthorizeRequest) (*response.AuthorizeResponse, error)
}

type authorize struct {
	Conf *config.SimpleConfig
}

func (s *authorize) Login(req *request.AuthorizeRequest) (res *response.AuthorizeResponse, err error) {
	val := &validate.AuthorizeRequestValidate{
		Conf: s.Conf,
		Req:  req,
		Res:  &response.AuthorizeResponse{},
	}

	if err := val.Validate(); err != nil {
		return nil, err
	}

	s.Conf.Logger.Info("authorize response type: %v, client need login: %v", request.AUTHORIZE_RESPONSE_CODE, val.Client.GetNeedLogin())
	err = s.createAuthorize(val)
	if err != nil {
		return nil, err
	}

	if val.User == nil || val.User.GetId() == "" {
		s.Conf.Logger.Error("user info is nil, user: %v", val.User)
		return nil, fmt.Errorf("need user login.")
	}

	if err := s.bindUserToCode(val); err != nil {
		return nil, err
	}

	return val.Res, nil
}

func (s *authorize) Register(req *request.AuthorizeRequest) (res *response.AuthorizeResponse, err error) {
	val := &validate.AuthorizeRequestValidate{
		Conf: s.Conf,
		Req:  req,
		Res:  &response.AuthorizeResponse{},
	}

	if err := val.Validate(); err != nil {
		return nil, err
	}

	s.Conf.Logger.Info("authorize response type: %v, client need login: %v", request.AUTHORIZE_RESPONSE_CODE, val.Client.GetNeedLogin())

	if req.ResponseType == request.AUTHORIZE_RESPONSE_REGISTER {
		val.User = &entity.User{
			Id:       uuid.UUID(uuid.New()).String(),
			Username: req.Username,
			Password: req.Password,
			EMail:    req.EMail,
			Mobile:   req.Mobile,
		}

		if err := s.Conf.Storage.User.Create(val.User); err != nil {
			s.Conf.Logger.Error("create user account error, user: %v", val.User)
			return nil, err
		}
	}

	err = s.createAuthorize(val)
	if err != nil {
		return nil, err
	}

	if req.ResponseType == request.AUTHORIZE_RESPONSE_LOGIN && val.Client.GetNeedLogin() {
		if err := s.bindUserToCode(val); err != nil {
			return nil, err
		}
	}

	return val.Res, nil
}

func (s *authorize) Authorization(req *request.AuthorizeRequest) (*response.AuthorizeResponse, error) {
	val := &validate.AuthorizeRequestValidate{
		Conf: s.Conf,
		Req:  req,
		Res:  &response.AuthorizeResponse{},
	}

	if err := val.Validate(); err != nil {
		return nil, err
	}

	if req.ResponseType == request.AUTHORIZE_RESPONSE_CODE && val.Client.GetNeedLogin() {
		val.Res.NeedLogin = true

		return val.Res, fmt.Errorf("client validate need user login.")
	}

	err := s.createAuthorize(val)
	if err != nil {
		return nil, err
	}

	return val.Res, nil
}

func (s *authorize) createAuthorize(val *validate.AuthorizeRequestValidate) (err error) {
	// generate token code
	val.Res.Code, err = s.Conf.AuthorizeCode.GenerateCode(val.Req)
	if err != nil {
		return fmt.Errorf("generate authorize code error: %s", err)
	}

	val.Res.ExpiresIn = s.Conf.AuthorizationExpiration
	val.Res.RedirectUri = val.Req.RedirectUri
	val.Res.Scope = val.Req.Scope
	val.Res.State = val.Req.State

	data := &entity.Authorize{}
	data.ExpiresIn = s.Conf.AccessExpiration
	data.RedirectUri = val.Req.RedirectUri
	data.Scope = val.Req.Scope
	data.Code = val.Res.Code
	data.ClientId = val.Req.ClientId
	data.Client = val.Client
	data.CodeChallenge = val.Req.CodeChallenge
	data.CodeChallengeMethod = val.Req.CodeChallengeMethod
	data.CreatedAt = val.Conf.Now()
	data.State = val.Req.State

	if val.Client.GetNeedLogin() {
		data.UserId = val.User.GetId()
		data.User = val.User
	}

	// save authorization token
	if err = s.Conf.Storage.Authorize.Create(data); err != nil {
		return fmt.Errorf("%s %s", config.ERROR_AUTHORIZE_CREATE_ERROR, err)
	}

	return err
}

// Login 登录入口
func (s *authorize) bindUserToCode(val *validate.AuthorizeRequestValidate) (err error) {
	if val.Client == nil {
		val.Conf.Logger.Error("bind user to code error: %v", val)
		return fmt.Errorf("client not exists.")
	}

	if !val.Client.GetNeedLogin() {
		return nil
	}

	if len(val.Req.Username) == 0 || len(val.Req.Password) == 0 {
		return fmt.Errorf("username or password is null.")
	}

	if val.User == nil || len(val.User.GetId()) == 0 {
		return fmt.Errorf("user storage not bind or user not exists.")
	}

	if len(val.Res.Code) == 0 {
		return fmt.Errorf("code error.")
	}

	if err := s.Conf.Storage.Authorize.BindUser(val.Res.Code, val.User.GetId()); err != nil {
		return err
	}

	return nil
}
