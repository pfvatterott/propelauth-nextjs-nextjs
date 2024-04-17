import { getUserOrRedirect, getCurrentUrl } from "@propelauth/nextjs/server/app-router";

const Home = async () => {
  const user = await getUserOrRedirect({ returnToCurrentPath: true });
  const response = await fetch("http://localhost:3000/api/exampleRoute");

  // Check for successful response status (optional but recommended)
  if (!response.ok) {
    throw new Error(`API call failed with status ${response.status}`);
  }

  // Parse the response body as JSON
  const data = await response.json();
  console.log(data)

  // Access the data from the response
  return <div>Hello {user.email}! </div>;
};

export default Home;