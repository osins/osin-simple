# osin-simple
Golang OAuth2 server library

例子代码：

```
storage := pg.New()

// ex.NewTestStorage implements the "osin.Storage" interface
conf := simple.NewServerConfig()
conf.AllowClientSecretInParams = true
conf.AccessExpiration = 1000000
conf.AllowedAccessTypes = osin.AllowedAccessType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN}
conf.AccessTokenGen = &accessTokenGenJWT

server := simple.NewSimpleServer(conf, storage)

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

// Access token endpoint (code, refresh code)
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
	
	if ctx.FormValue("refresh_token") != "" {
		req.AccessData = &osin.AccessData{
			RefreshToken: ctx.FormValue("refresh_token"),
		}
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

```
