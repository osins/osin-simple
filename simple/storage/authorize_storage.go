package storage

import (
	"github.com/osins/osin-simple/simple/model/face"
)

type AuthorizeStorage interface {
	Get(code string) (face.Authorize, error)
	Create(authorize face.Authorize) error
	BindUser(code string, userId string) error
}
