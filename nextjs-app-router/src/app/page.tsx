import {getUserOrRedirect, getUser} from "@propelauth/nextjs/server/app-router";
import LogoutButton from "@/components/LogoutButton";
import LoginButton from "@/components/LoginButton"

const Home = async() => {
  const user = await getUser()
  // const logoutFn = useLogoutFunction()
  return (
    <main>
      <h2>{user?.email}</h2>
      <LogoutButton></LogoutButton>
      <LoginButton></LoginButton>
    </main>
  )
}
export default Home 