package entity

import (
	"time"
)

// User define
type User struct {
	Id string

	Username string

	Password []byte

	Salt []byte

	EMail string

	Mobile string

	// Date created
	CreatedAt time.Time
}

func (s *User) GetId() string {
	return s.Id
}

func (s *User) GetPassword() []byte {
	return s.Password
}

func (s *User) GetSalt() []byte {
	return s.Salt
}

func (s *User) GetUsername() string {
	return s.Username
}

func (s *User) GetMobile() string {
	return s.Mobile
}

func (s *User) GetEmail() string {
	return s.EMail
}
