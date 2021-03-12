package response

import "github.com/osins/osin-simple/simple/model/face"

type AccessResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int32     `json:"expires_in"`
	User         face.User `json:"user"`
}
