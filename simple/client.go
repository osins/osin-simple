package simple

type Client interface {
}

type client struct {
	Server *SimpleServer
}
