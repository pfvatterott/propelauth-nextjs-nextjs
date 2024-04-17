import { getUser, getCurrentUrl } from "@propelauth/nextjs/server/app-router";
import { redirect } from "next/navigation";
import { cookies } from 'next/headers'

const Home = async ({
  searchParams,
}: {
  searchParams: { [key: string]: string | string[] | undefined };
}) => {
  const user = await getUser()
  console.log(user)
  const orgId = searchParams["orgId"]

  if (user) {
    return (<h2>hi {user.email}</h2>)
  }
  else if (!user) {
    redirect(`/api/auth/login?return_to_path=${encodeURIComponent(`/test?orgId=${orgId}`)}`);
  }
}

export default Home;