package entity

import (
	"time"
)

// User define
type User struct {
	Id string

	Username string

	Password string

	EMail string

	Mobile string

	// Date created
	CreatedAt time.Time
}

func (s *User) GetId() string {
	return s.Id
}

func (s *User) GetUsername() string {
	return s.Username
}

func (s *User) GetPassword() string {
	return s.Password
}

func (s *User) GetMobile() string {
	return s.Mobile
}

func (s *User) GetEmail() string {
	return s.EMail
}
