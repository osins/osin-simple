# osin-simple
Golang OAuth2 server library

本代码库主要解决开源oauth2 server 库( https://github.com/openshift/osin )过分依赖net/http的问题，由于在至少我的项目中一般来说是不会直接使用net/http的，假如我们依赖于fiber或者gin这种web框架，那么原先的osin库就不太合适了，它过分紧密的与net/http关联在了一起，不方便与其他web框架集成，所以我在osin的基础上进行了剥离，便于与其他web框架集成。

JWT生成tokan的例子代码：
```
package main

import (
	"crypto/rsa"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"github.com/openshift/osin"
	"github.com/wangsying/osin-simple/simple"
	"github.com/wangsying/osin-storage/storage/pg"
)

var (
	_, f, _, _ = runtime.Caller(0)
	BasePATH   = filepath.Dir(f)
	ENVFile    = BasePATH + "/.env"
)

func LoadEnv() {
	fmt.Printf("init env start. path: %s\n", ENVFile)
	err := godotenv.Load(ENVFile)
	if err != nil {
		fmt.Printf("Error loading .env file: " + err.Error())
	}

	fmt.Printf("init env complete.")
}

type User struct {
	Id       string
	Realname string
	EMail    string
	Password string
}

type AccessTokenGenJWT struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func (c *AccessTokenGenJWT) GenerateAccessToken(data *osin.AccessData, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	// generate JWT access token

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"cid": data.Client.GetId(),
		"exp": data.ExpireAt().Unix(),
	})

	accesstoken, err = token.SignedString(c.PrivateKey)
	if err != nil {
		return "", "", err
	}

	fmt.Printf("generaterefresh: %v\n", generaterefresh)
	if !generaterefresh {
		return
	}

	// generate JWT refresh token
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"cid": data.Client.GetId(),
		"exp": data.ExpireAt().Unix(),
	})

	refreshtoken, err = token.SignedString(c.PrivateKey)
	if err != nil {
		return "", "", err
	}
	return
}

func main() {
	LoadEnv()

	var err error

	// u := &User{
	// 	Id:       "8877",
	// 	Realname: "richard",
	// 	EMail:    "296907@qq.com",
	// 	Password: "123456",
	// }

	// client := &osin.DefaultClient{
	// 	Id:          "1234",
	// 	Secret:      "aabbccdd",
	// 	RedirectUri: "http://localhost:14000/appauth",
	// 	UserData:    u,
	// }
	// pg.NewClientManage().Delete(client.Id)
	// pg.NewClientManage().Create(client)
	// f := pg.NewClientManage().First(client.Id)
	// b1, err1 := json.Marshal(f)
	// if err != nil {
	// 	fmt.Printf(err1.Error())
	// } else {
	// 	fmt.Printf("\nclient manage first: %s\n", b1)
	// }

	var accessTokenGenJWT AccessTokenGenJWT
	if accessTokenGenJWT.PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privatekeyPEM); err != nil {
		fmt.Printf("ERROR: %s\n", err)
		return
	}

	if accessTokenGenJWT.PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(publickeyPEM); err != nil {
		fmt.Printf("ERROR: %s\n", err)
		return
	}

	storage := pg.New()

	// ex.NewTestStorage implements the "osin.Storage" interface
	conf := simple.NewServerConfig()
	conf.AllowClientSecretInParams = true
	conf.AccessExpiration = 1000000
	conf.AllowedAccessTypes = osin.AllowedAccessType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN, osin.PASSWORD}
	conf.AccessTokenGen = &accessTokenGenJWT
	conf.Storage = storage
	conf.ValidateUser = pg.NewValidateUser()

	server := simple.NewSimpleServer(conf)

	app := fiber.New()

	// Authorization code endpoint
	app.Get("/oauth/authorize", func(ctx *fiber.Ctx) error {
		req := &osin.AuthorizeRequest{
			Client: &osin.DefaultClient{
				Id:          ctx.Query("client_id"),
				Secret:      ctx.Query("client_secret"),
				RedirectUri: ctx.Query("redirect_uri"),
			},
			RedirectUri: ctx.Query("redirect_uri"),
			State:       ctx.Query("state"),
			Type:        osin.AuthorizeRequestType(ctx.Query("response_type")),
		}

		ad, err := simple.NewAuthorize(server).Authorization(req)
		if err != nil {
			return err
		}

		params := url.Values{
			"code":  {ad.Code},
			"state": {ad.State},
		}

		ctx.Redirect(fmt.Sprintf("%s?%s", ad.Client.GetRedirectUri(), params.Encode()))

		return nil
	})

	// Access token endpoint
	app.Post("/oauth/token", func(ctx *fiber.Ctx) error {
		req := &osin.AccessRequest{
			Client: &osin.DefaultClient{
				Id:          ctx.FormValue("client_id"),
				Secret:      ctx.FormValue("client_secret"),
				RedirectUri: ctx.FormValue("redirect_uri"),
			},
			Type:            osin.AccessRequestType(ctx.FormValue("grant_type")),
			Code:            ctx.FormValue("code"),
			Scope:           ctx.FormValue("scope"),
			CodeVerifier:    ctx.FormValue("code_verifier"),
			RedirectUri:     ctx.FormValue("redirect_uri"),
			GenerateRefresh: true,
			Expiration:      server.Config.AccessExpiration,
		}
		fmt.Println("grant type:" + req.Type)
		if ctx.FormValue("refresh_token") != "" {
			req.AccessData = &osin.AccessData{
				RefreshToken: ctx.FormValue("refresh_token"),
			}
		}

		if ctx.FormValue("grant_type") == "password" {
			req.Username = ctx.FormValue("username")
			req.Password = ctx.FormValue("password")
		}

		res, err := simple.NewAccess(server).Access(req)
		if err != nil {
			return err
		}

		ctx.JSON(res)

		return nil
	})

	app.Get("/info", func(ctx *fiber.Ctx) error {
		code, err := simple.NewToken().AuthorizationToCode(ctx.Get("Authorization"))
		if err != nil {
			return err
		}

		req := &osin.InfoRequest{
			Code: code,
			AccessData: &osin.AccessData{
				Client: &osin.DefaultClient{
					Id:          ctx.FormValue("client_id"),
					Secret:      ctx.FormValue("client_secret"),
					RedirectUri: ctx.FormValue("redirect_uri"),
				},
				Scope:       ctx.FormValue("scope"),
				RedirectUri: ctx.FormValue("redirect_uri"),
			},
		}

		if ad, err := simple.NewInfo(server).Info(req); err != nil {
			return err
		} else {
			ctx.JSON(ad)
		}

		return nil
	})

	app.Listen(":14000")
}

var (
	privatekeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----`)

	publickeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7
mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBp
HssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2
XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy
7wIDAQAB
-----END PUBLIC KEY-----`)
)


```
