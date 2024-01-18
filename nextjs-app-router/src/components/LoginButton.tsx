"use client"

import {useRedirectFunctions} from "@propelauth/nextjs/client";

export default function SignupAndLoginButtons() {
	const {redirectToSignupPage, redirectToLoginPage} = useRedirectFunctions()
	return <>
		<button onClick={() => redirectToLoginPage()}>Log in</button>
	</>
}
