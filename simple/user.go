package simple

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/osins/osin-simple/simple/config"
	"github.com/osins/osin-simple/simple/model/entity"
	"github.com/osins/osin-simple/simple/request"
)

func NewUser(s *SimpleServer) User {
	return &user{
		Conf: s.Config,
	}
}

type User interface {
	Register(req *request.AuthorizeRequest) error
}

type user struct {
	Conf *config.SimpleConfig
}

func (s *user) Register(req *request.AuthorizeRequest) error {
	salt, err := s.Conf.PasswordGen.Salt()
	if err != nil {
		return fmt.Errorf("create user salt error: %s", err)
	}

	password := s.Conf.PasswordGen.Generate([]byte(req.Password), salt)
	if !s.Conf.PasswordGen.Compare(req.Password, salt, password) {
		return fmt.Errorf("create user password error: %s", "password compare faild.")
	}

	u := &entity.User{
		Id:       uuid.UUID(uuid.New()).String(),
		Username: req.Username,
		Password: password,
		Salt:     salt,
		EMail:    req.EMail,
		Mobile:   req.Mobile,
	}

	if err := s.Conf.Storage.User.Create(u); err != nil {
		return err
	}

	return nil
}
