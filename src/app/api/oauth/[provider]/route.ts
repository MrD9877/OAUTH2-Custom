import { getCodeVerifier, OAuthClient, OAuthProviders, validState } from "@/utility/authClient";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { NextRequest } from "next/server";
import { z } from "zod";

export async function GET(req: NextRequest, { params }: { params: Promise<{ provider: string }> }) {
  const { provider: rawProvider } = await params;
  const cookie = await cookies();
  console.log(rawProvider);
  const code = req.nextUrl.searchParams.get("code");
  const state = req.nextUrl.searchParams.get("state");
  const provider = z.enum(OAuthProviders).parse(rawProvider);
  if (typeof code !== "string") return redirect("/login?error=Failed to connect. Please try again id 3");
  try {
    const isValidState = validState(state, cookie);
    if (!isValidState) throw Error("OAuthstate is not valid");
    const OAuthUser = await new OAuthClient(provider).fetchUser(code, getCodeVerifier(cookie));
    // const user = await createUserAccount(OAuthUser);
    console.log({ OAuthUser });
  } catch (err) {
    console.log(err);
    return redirect("/login?error=Failed to connect. Please try again id 4");
  }
  return redirect("/");
}

// function createUserAccount(OAuthUser:) {

// }
