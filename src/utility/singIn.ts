"use server";
import { redirect } from "next/navigation";
import { OAuthClient, OAuthProvidersType } from "./authClient";
import { cookies } from "next/headers";

export const signIn = async (provider: OAuthProvidersType) => {
  const cookie = await cookies();
  const authclient = new OAuthClient(provider);
  return redirect(authclient.createAuthUrl(cookie));
};
