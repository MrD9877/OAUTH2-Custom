import { ReadonlyRequestCookies } from "next/dist/server/web/spec-extension/adapters/request-cookies";
import { redirect } from "next/navigation";
import { z } from "zod";
import crypto from "crypto";

export const OAuthProviders = ["google", "discord"] as const;
export type OAuthProvidersType = (typeof OAuthProviders)[number];
const COOKIE_STATE_EXPIRE_IN_SEC = 60 * 5;
const COOKIE_STATE_KEY = "oAuthState";
const COOKIE_VERIFIER_EXPIRE_IN_SEC = 60 * 5;
const COOKIE_VERIFIER_KEY = "oAuthVerifier";

type UrlsType = {
  clientId: string | undefined;
  auth: URL;
  token: string;
  user: string;
  clientSecret: string;
  scope: string[];
};
export type OAuthUser = {
  username: string;
  id: string;
  verified_email: boolean | undefined;
  avatar: string;
  email: string;
};

const TokenSchema = z.object({
  token_type: z.string(),
  access_token: z.string(),
});
const GoogleUserSchema = z.object({
  id: z.string(),
  email: z.string(),
  verified_email: z.boolean(),
  name: z.string(),
  picture: z.string().url(),
});
const DiscordUserSchema = z.object({
  id: z.string(),
  email: z.string(),
  verified: z.boolean(),
  username: z.string(),
  avatar: z.string(),
});

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

export class OAuthClient {
  provider: OAuthProvidersType;
  constructor(provider: OAuthProvidersType) {
    this.provider = provider;
  }
  private redirectUrl() {
    return new URL(this.provider, process.env.OAUTH_URL_BASE);
  }
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
  createAuthUrl(cookies: ReadonlyRequestCookies) {
    const url = urls[this.provider].auth;
    url.searchParams.set("client_id", urls[this.provider].clientId || "");
    url.searchParams.set("redirect_uri", this.redirectUrl().toString());
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", urls[this.provider].scope.join(" "));
    url.searchParams.set("state", this.createState(cookies));
    url.searchParams.set("state", this.createState(cookies));
    url.searchParams.set("code_challenge", crypto.hash("sha256", this.code_verifier(cookies), "base64url"));
    url.searchParams.set("code_challenge_method", "S256");
    return url.toString();
  }

  private async fetchToken(code: string, codeVerifier: string | undefined) {
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
      .then((res) => res.json())
      .then((rawData) => {
        const { data, success, error } = TokenSchema.safeParse(rawData);
        if (!success) throw Error(error.message);
        return data;
      });
  }

  private async parseUser(rawData: unknown, provider: OAuthProvidersType): Promise<OAuthUser> {
    let schema;

    if (provider === "google") schema = GoogleUserSchema;
    else if (provider === "discord") schema = DiscordUserSchema;
    else redirect("/login?error=Failed to connect. Please try again id 1");
    const { data: userData, success, error } = await schema.safeParse(rawData);
    let user: OAuthUser;
    if (!success) throw Error(error.message);
    if (provider === "google") {
      const data = userData as z.infer<typeof GoogleUserSchema>;
      user = {
        username: data.name,
        email: data.email,
        id: data.id,
        verified_email: data.verified_email,
        avatar: data.picture,
      };
    } else if (provider === "discord") {
      const data = userData as z.infer<typeof DiscordUserSchema>;
      user = {
        username: data.username,
        email: data.email,
        id: data.id,
        verified_email: data.verified,
        avatar: `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png`,
      };
    } else {
      redirect("/login?error=Failed to connect. Please try again id 5");
    }

    return user;
  }

  async fetchUser(code: string, codeVerifier: string | undefined): Promise<OAuthUser> {
    const { token_type, access_token } = await this.fetchToken(code, codeVerifier);
    return fetch(urls[this.provider].user, {
      headers: {
        Authorization: `${token_type} ${access_token}`,
      },
    })
      .then((res) => res.json())
      .then((rawData) => {
        const user = this.parseUser(rawData, this.provider).then((data) => data);
        return user;
      });
  }
}
export function validState(state: string | null, cookie: ReadonlyRequestCookies): boolean {
  const cookieState = cookie.get(COOKIE_STATE_KEY)?.value;
  if (!cookieState || !state) return false;
  if (cookieState === state) return true;
  return false;
}
export function getCodeVerifier(cookie: ReadonlyRequestCookies) {
  const cookieState = cookie.get(COOKIE_VERIFIER_KEY)?.value;
  return cookieState;
}
