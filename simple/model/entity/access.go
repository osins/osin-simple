package entity

import (
	"time"

	"github.com/osins/osin-simple/simple/model/face"
)

// Access define
type Access struct {
	// Access token
	AccessToken string `gorm:"primaryKey;->;<-:create;"`

	ClientId string

	Client face.Client

	UserId string

	User face.User

	// Refresh Token. Can be blank
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Date created
	CreatedAt time.Time

	DeletedAt time.Time
}

// GetAccessToken method define
func (s *Access) GetAccessToken() string {
	return s.AccessToken
}

// GetRefreshToken method define
func (s *Access) GetRefreshToken() string {
	return s.RefreshToken
}

// GetClient method define
func (s *Access) GetClient() face.Client {
	return s.Client
}

// GetUser method define
func (s *Access) GetUser() face.User {
	return s.User
}

// GetExpiresIn method define
func (s *Access) GetExpiresIn() int32 {
	return s.ExpiresIn
}

// GetScope method define
func (s *Access) GetScope() string {
	return s.Scope
}

// IsExpired returns true if access expired
func (d *Access) GetCreatedAt() time.Time {
	return d.CreatedAt
}

// IsExpired returns true if access expired
func (d *Access) GetDeletedAt() time.Time {
	return d.DeletedAt
}

// IsExpired returns true if access expired
func (d *Access) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpiredAt returns true if access expires at time 't'
func (d *Access) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *Access) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}
