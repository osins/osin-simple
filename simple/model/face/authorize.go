package face

import (
	"time"
)

type Authorize interface {
	GetCode() string
	GetClient() Client
	GetUser() User
	GetState() string
	GetExpiresIn() int32
	GetScope() string
	GetRedirectUri() string
	GetCodeChallenge() string
	GetCodeChallengeMethod() string
	GetCreatedAt() time.Time
	GetDeletedAt() time.Time
	IsExpired() bool
	IsExpiredAt(t time.Time) bool
	ExpireAt() time.Time
}
