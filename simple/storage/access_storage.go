package storage

import (
	"github.com/osins/osin-simple/simple/model/face"
)

type AccessStorage interface {
	Create(data face.Access) error
	BindUser(token string, userId string) error
	Get(token string) (face.Access, error)
	GetByRefreshToken(token string) (face.Access, error)
	RemoveAuthorize(token string) error
	RemoveRefresh(token string) error
}
