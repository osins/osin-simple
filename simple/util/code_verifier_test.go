package util

import (
	"fmt"
	"testing"
)

func TestGenCodeVerifier(t *testing.T) {
	var (
		v string
		e error
	)

	c := NewCodeVerifier("helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworld")
	_, e = c.Validate()
	if e != nil {
		fmt.Printf("err: %s\n", e.Error())
		return
	}

	v, e = c.Plain()
	if e != nil {
		fmt.Printf("err: %s\n", e.Error())
		return
	}

	fmt.Printf("plain: %s\n", v)

	v, e = c.Sha256()
	if e != nil {
		fmt.Printf("err: %s\n", e.Error())
		return
	}

	fmt.Printf("sha256: %s\n", v)
}
