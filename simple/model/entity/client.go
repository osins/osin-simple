package entity

import (
	"time"
)

// Client define
type Client struct {
	Id          string
	Secret      string
	RedirectUri string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   time.Time
	NeedLogin   bool
	NeedRefresh bool
}

// GetId method define
func (d *Client) GetId() string {

	return d.Id
}

func (d *Client) GetNeedLogin() bool {
	return d.NeedLogin
}

// GetSecret method define
func (d *Client) GetSecret() string {

	return d.Secret
}

// GetRedirectUri method define
func (d *Client) GetRedirectUri() string {

	return d.RedirectUri
}

func (d *Client) GetNeedRefresh() bool {
	return d.NeedRefresh
}

// Implement the ClientSecretMatcher interface
// ClientSecretMatches method define
func (d *Client) ClientSecretMatches(secret string) bool {
	return d.Secret == secret
}
