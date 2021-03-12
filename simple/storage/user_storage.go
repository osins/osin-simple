package storage

import "github.com/osins/osin-simple/simple/model/face"

type UserStorage interface {
	Create(face.User) error
	GetId(code string, password string) (string, error)
	GetById(userId string) (face.User, error)
	GetByPassword(code string, password string) (face.User, error)
}
