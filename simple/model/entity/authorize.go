package entity

import (
	"time"

	"github.com/osins/osin-simple/simple/model/face"
)

// Authorize define
type Authorize struct {
	// Authorization code
	Code string

	ClientId string

	// Client information
	Client face.Client

	UserId string

	User face.User

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// State data from request
	State string

	// Date created
	CreatedAt time.Time

	DeletedAt time.Time

	// Optional code_challenge as described in rfc7636
	CodeChallenge string

	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}

// GetCode func define
func (d *Authorize) GetCode() string {
	return d.Code
}

// GetClient func define
func (d *Authorize) GetClient() face.Client {
	return d.Client
}

// GetUser func define
func (d *Authorize) GetUser() face.User {
	return d.User
}

// GetState func define
func (d *Authorize) GetState() string {
	return d.State
}

// GetExpiresIn func define
func (d *Authorize) GetExpiresIn() int32 {
	return d.ExpiresIn
}

// GetScope func define
func (d *Authorize) GetScope() string {
	return d.Scope
}

// GetRedirectUri func define
func (d *Authorize) GetRedirectUri() string {
	return d.RedirectUri
}

// GetCodeChallenge func define
func (d *Authorize) GetCodeChallenge() string {
	return d.CodeChallenge
}

// GetCodeChallengeMethod func define
func (d *Authorize) GetCodeChallengeMethod() string {
	return d.CodeChallengeMethod
}

// GetCreatedAt func define
func (d *Authorize) GetCreatedAt() time.Time {
	return d.CreatedAt
}

// GetDeletedAt func define
func (d *Authorize) GetDeletedAt() time.Time {
	return d.DeletedAt
}

// IsExpired returns true if access expired
func (d *Authorize) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpiredAt returns true if access expires at time 't'
func (d *Authorize) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *Authorize) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}
