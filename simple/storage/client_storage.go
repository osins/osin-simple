package storage

import "github.com/osins/osin-simple/simple/model/face"

type ClientStorage interface {
	Create(face.Client) error
	Get(clientId string) (face.Client, error)
}
