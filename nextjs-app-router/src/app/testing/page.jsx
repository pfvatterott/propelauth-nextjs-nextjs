"use client";
import {
  useUser,
  useLogoutFunction,
  useRedirectFunctions,
  useHostedPageUrls
} from "@propelauth/nextjs/client";
import Link from 'next/link';

const Testing = () => {
  const { loading, user, setActiveOrg } = useUser();

  const {
    getLoginPageUrl
} = useHostedPageUrls()

  const logoutFn = useLogoutFunction();

  const { redirectToSignupPage, redirectToLoginPage, redirectToAccountPage } = useRedirectFunctions();
  const sortOrgsByName = (a, b) => {
    const orgAName = a.orgName.toLowerCase();
    const orgBName = b.orgName.toLowerCase();
    return orgAName.localeCompare(orgBName);
  };

  async function handleOrgChange(orgId) {
    const result = await setActiveOrg(orgId);
    if (!result) {
      console.log('error')
    }
  
  }
  let sortedOrgs;
  let orgs;
  let activeOrg;
  if (user) {
    orgs = user.getOrgs();
    sortedOrgs = orgs?.slice().sort(sortOrgsByName) || [];
    activeOrg = user.getActiveOrg();
  }

  async function handleLoginWithSaml() {
    window.location.href =
      "https://38291285.propelauthtest.com/saml/fa5514e1-c816-4499-87ac-7a81cea07dbe/login";
    return;
  }

  if (loading) {
    return <div>Loading...</div>;
  } else if (user && activeOrg) {
    console.log(user.properties.metadata)
    return (
      <div>
        <button onClick={handleLoginWithSaml}>Login with SAML</button>
        <h2>Active Org = {user.getActiveOrg().orgName}</h2>
        {orgs?.map((org) => (
          <button key={org.orgId} onClick={() => handleOrgChange(org.orgId)}>
            {org.orgId === activeOrg
              ? `Active Org: ${org.orgName}`
              : org.orgName}
          </button>
        ))}
        <button onClick={logoutFn}>Logout</button>
      </div>
    );
  } else {
    return <div>
    <Link href={getLoginPageUrl()}>Login</Link>
  </div>

  }
};
export default Testing;


    
