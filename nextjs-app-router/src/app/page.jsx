import {getUser, getAccessToken} from "@propelauth/nextjs/server/app-router";
import LogoutButton from "@/components/LogoutButton";


export default async function Home() {
  const user = await getUser()

  if (user) {
    return (
      <div>
        <p>User: {user.email}</p>
        <LogoutButton />
      </div>
    );
  } else {
    return (<h2>Please login</h2>)
  }
}
