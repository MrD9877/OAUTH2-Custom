# OAUTH2

## Redirect TO provider

-----> redirect to authUrl with client_id,scope,redirecturl,response-type\

```
 private redirectUrl() {
    return new URL(this.provider, process.env.OAUTH_URL_BASE);
  }
  createAuthUrl() {
    const url = urls[this.provider].auth;
    url.searchParams.set("client_id", urls[this.provider].clientId || "");
    url.searchParams.set("redirect_uri", this.redirectUrl().toString());
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", urls[this.provider].scope.join(" "));
    url.searchParams.set("state", this.createState(cookies));
    url.searchParams.set("code_challenge", crypto.hash("sha256", this.code_verifier(cookies), "base64url"));
    url.searchParams.set("code_challenge_method", "S256");
    return url.toString();
  }
```

```
const urls: { [key in OAuthProvidersType]: UrlsType } = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    auth: new URL("https://accounts.google.com/o/oauth2/v2/auth"),
    token: "https://oauth2.googleapis.com/token",
    user: "https://www.googleapis.com/oauth2/v2/userinfo",
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
    scope: ["openid", "email", "profile"],
  },
  discord: {
    clientId: process.env.DISCORD_CLIENT_ID,
    auth: new URL("https://discord.com/oauth2/authorize"),
    token: "https://discord.com/api/oauth2/token",
    user: "https://discord.com/api/users/@me",
    clientSecret: process.env.DISCORD_CLIENT_SECRET || "",
    scope: ["openid", "email", "identify"],
  },
};
```

## Get token

-------> Get code from urlParams of redirectUrl

```
 return fetch(urls[this.provider].token, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "aplication/json",
      },
      body: new URLSearchParams({
        code,
        redirect_uri: this.redirectUrl().toString(),
        client_id: urls[this.provider].clientId || "",
        client_secret: urls[this.provider].clientSecret || "",
        grant_type: "authorization_code",
        code_verifier: codeVerifier || "",
      }),
    })
```

## getUser

```
 const { token_type, access_token } = await this.fetchToken(code);
    return fetch(urls[this.provider].user, {
      headers: {
        Authorization: `${token_type} ${access_token}`,
      },
    })
```

## Advance Security OAuth

### State

Send a crypted string which get returns in callbackUrl to check if callBack is comming from trusted provider

```
    url.searchParams.set("state", this.createState(cookies));
```

```
  private createState(cookies: ReadonlyRequestCookies) {
    const state = crypto.randomBytes(64).toString("hex").normalize();
    cookies.set(COOKIE_STATE_KEY, state, {
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      expires: Date.now() + COOKIE_STATE_EXPIRE_IN_SEC * 1000,
    });
    return state;
  }
```

### Code_Challenge

Send a crypted hashed in sha256 string which get returns in callbackUrl to check if callBack is comming from trusted provider

```
 url.searchParams.set("code_challenge", crypto.hash("sha256", this.code_verifier(cookies), "base64url"));
 url.searchParams.set("code_challenge_method", "S256");
```

```
  private code_verifier(cookies: ReadonlyRequestCookies) {
    const state = crypto.randomBytes(64).toString("hex").normalize();
    cookies.set(COOKIE_VERIFIER_KEY, state, {
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      expires: Date.now() + COOKIE_VERIFIER_EXPIRE_IN_SEC * 1000,
    });
    return state;
  }
```

send It with body to auth with provider

```
       code_verifier: codeVerifier || "",
```
