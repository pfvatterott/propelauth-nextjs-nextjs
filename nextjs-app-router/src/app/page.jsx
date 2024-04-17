"use client"
import {useUser, useRedirectFunctions} from "@propelauth/nextjs/client";
import LogoutButton from "@/components/LogoutButton";
import LoginButton from "@/components/LoginButton"
import { useEffect } from "react";

const Home = () => {
  const { loading, user, setActiveOrg } = useUser()
  
  
  if (loading) {
    return <div>Loading...</div>
  } else if (user) {
    setActiveOrg(null)
    console.log(user)
    return (
      <div>
       <h2>Hello, {user.email}</h2>
      </div>
    );
  }
  else {
    return (
      <LoginButton></LoginButton>
    )
  }
}
export default Home 