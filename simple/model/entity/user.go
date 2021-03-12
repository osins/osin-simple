package entity

import (
	"time"

	"github.com/google/uuid"
)

// User define
type User struct {
	Id uuid.UUID

	Username string

	Password string

	EMail string

	Mobile string

	// Date created
	CreatedAt time.Time
}

func (s *User) GetId() string {
	return s.Id.String()
}

func (s *User) GetUsername() string {
	return s.Id.String()
}

func (s *User) GetPassword() string {
	return s.Id.String()
}

func (s *User) GetMobile() string {
	return s.Id.String()
}

func (s *User) GetEmail() string {
	return s.Id.String()
}
func (s *User) GetCode() string {
	return s.Id.String()
}
