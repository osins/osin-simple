package storage

import "github.com/osins/osin-simple/simple/model/face"

type UserStorage interface {
	Create(face.User) error
	GetId(code string, password string) (string, error)
	GetById(userId string) (face.User, error)
	GetByCode(code string) (face.User, error)
}
