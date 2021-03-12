package face

import "time"

type Access interface {
	GetAccessToken() string
	GetRefreshToken() string
	GetClient() Client
	GetUser() User
	GetExpiresIn() int32
	GetScope() string
	GetCreatedAt() time.Time
	GetDeletedAt() time.Time
	IsExpired() bool
	IsExpiredAt(t time.Time) bool
	ExpireAt() time.Time
}
