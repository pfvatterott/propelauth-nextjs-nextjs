import React from 'react';

declare enum SocialLoginProvider {
    Google = "Google",
    GitHub = "GitHub",
    Microsoft = "Microsoft",
    Slack = "Slack",
    LinkedIn = "LinkedIn",
    Salesforce = "Salesforce",
    Xero = "Xero",
    QuickBooksOnline = "QuickBooks Online"
}
declare enum SamlLoginProvider {
    Google = "Google",
    Rippling = "Rippling",
    OneLogin = "OneLogin",
    JumpCloud = "JumpCloud",
    Okta = "Okta",
    Azure = "Azure",
    Duo = "Duo",
    Generic = "Generic"
}
type InternalPasswordLoginMethod = {
    login_method: 'password';
};
type InternalMagicLinkLoginMethod = {
    login_method: 'magic_link';
};
type InternalSocialSsoLoginMethod = {
    login_method: 'social_sso';
    provider: SocialLoginProvider;
};
type InternalEmailConfirmationLinkLoginMethod = {
    login_method: 'email_confirmation_link';
};
type InternalSamlSsoLoginMethod = {
    login_method: 'saml_sso';
    provider: SamlLoginProvider;
    org_id: string;
};
type InternalImpersonationLoginMethod = {
    login_method: 'impersonation';
};
type InternalGeneratedFromBackendApiLoginMethod = {
    login_method: 'generated_from_backend_api';
};
type InternalUnknownLoginMethod = {
    login_method: 'unknown';
};
type InternalLoginMethod = InternalPasswordLoginMethod | InternalMagicLinkLoginMethod | InternalSocialSsoLoginMethod | InternalEmailConfirmationLinkLoginMethod | InternalSamlSsoLoginMethod | InternalImpersonationLoginMethod | InternalGeneratedFromBackendApiLoginMethod | InternalUnknownLoginMethod;
type PasswordLoginMethod = {
    loginMethod: 'password';
};
type MagicLinkLoginMethod = {
    loginMethod: 'magic_link';
};
type SocialSsoLoginMethod = {
    loginMethod: 'social_sso';
    provider: SocialLoginProvider;
};
type EmailConfirmationLinkLoginMethod = {
    loginMethod: 'email_confirmation_link';
};
type SamlSsoLoginMethod = {
    loginMethod: 'saml_sso';
    provider: SamlLoginProvider;
    orgId: string;
};
type ImpersonationLoginMethod = {
    loginMethod: 'impersonation';
};
type GeneratedFromBackendApiLoginMethod = {
    loginMethod: 'generated_from_backend_api';
};
type UnknownLoginMethod = {
    loginMethod: 'unknown';
};
type LoginMethod = PasswordLoginMethod | MagicLinkLoginMethod | SocialSsoLoginMethod | EmailConfirmationLinkLoginMethod | SamlSsoLoginMethod | ImpersonationLoginMethod | GeneratedFromBackendApiLoginMethod | UnknownLoginMethod;

declare class UserFromToken {
    userId: string;
    activeOrgId?: string;
    orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo;
    email: string;
    firstName?: string;
    lastName?: string;
    username?: string;
    properties?: {
        [key: string]: unknown;
    };
    loginMethod?: LoginMethod;
    legacyUserId?: string;
    impersonatorUserId?: string;
    constructor(userId: string, email: string, orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo, firstName?: string, lastName?: string, username?: string, legacyUserId?: string, impersonatorUserId?: string, properties?: {
        [key: string]: unknown;
    }, activeOrgId?: string, loginMethod?: LoginMethod);
    getActiveOrg(): OrgMemberInfo | undefined;
    getActiveOrgId(): string | undefined;
    getOrg(orgId: string): OrgMemberInfo | undefined;
    getOrgByName(orgName: string): OrgMemberInfo | undefined;
    getOrgs(): OrgMemberInfo[];
    isImpersonating(): boolean;
    static fromJSON(json: string): UserFromToken;
    static fromJwtPayload(payload: InternalUser): UserFromToken;
}
type OrgIdToOrgMemberInfo = {
    [orgId: string]: OrgMemberInfo;
};
declare class OrgMemberInfo {
    orgId: string;
    orgName: string;
    orgMetadata: {
        [key: string]: any;
    };
    urlSafeOrgName: string;
    userAssignedRole: string;
    userInheritedRolesPlusCurrentRole: string[];
    userPermissions: string[];
    constructor(orgId: string, orgName: string, orgMetadata: {
        [key: string]: any;
    }, urlSafeOrgName: string, userAssignedRole: string, userInheritedRolesPlusCurrentRole: string[], userPermissions: string[]);
    isRole(role: string): boolean;
    isAtLeastRole(role: string): boolean;
    hasPermission(permission: string): boolean;
    hasAllPermissions(permissions: string[]): boolean;
    static fromJSON(json: string): OrgMemberInfo;
    get assignedRole(): string;
    get inheritedRolesPlusCurrentRole(): string[];
    get permissions(): string[];
}
type InternalOrgMemberInfo = {
    org_id: string;
    org_name: string;
    org_metadata: {
        [key: string]: any;
    };
    url_safe_org_name: string;
    user_role: string;
    inherited_user_roles_plus_current_role: string[];
    user_permissions: string[];
};
type InternalUser = {
    user_id: string;
    org_member_info?: InternalOrgMemberInfo;
    org_id_to_org_member_info?: {
        [org_id: string]: InternalOrgMemberInfo;
    };
    email: string;
    first_name?: string;
    last_name?: string;
    username?: string;
    properties?: {
        [key: string]: unknown;
    };
    login_method?: InternalLoginMethod;
    legacy_user_id?: string;
    impersonatorUserId?: string;
};

declare class User {
    userId: string;
    email: string;
    emailConfirmed: boolean;
    hasPassword: boolean;
    username?: string;
    firstName?: string;
    lastName?: string;
    pictureUrl?: string;
    orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo;
    activeOrgId?: string;
    mfaEnabled: boolean;
    canCreateOrgs: boolean;
    updatePasswordRequired: boolean;
    createdAt: number;
    lastActiveAt: number;
    properties?: {
        [key: string]: unknown;
    };
    legacyUserId?: string;
    impersonatorUserId?: string;
    constructor({ userId, email, emailConfirmed, hasPassword, username, firstName, lastName, pictureUrl, orgIdToOrgMemberInfo, activeOrgId, mfaEnabled, canCreateOrgs, updatePasswordRequired, createdAt, lastActiveAt, legacyUserId, properties, impersonatorUserId, }: {
        userId: string;
        email: string;
        emailConfirmed: boolean;
        hasPassword: boolean;
        username?: string;
        firstName?: string;
        lastName?: string;
        pictureUrl?: string;
        orgIdToOrgMemberInfo?: OrgIdToOrgMemberInfo;
        activeOrgId?: string;
        mfaEnabled: boolean;
        canCreateOrgs: boolean;
        updatePasswordRequired: boolean;
        createdAt: number;
        lastActiveAt: number;
        legacyUserId?: string;
        properties?: {
            [key: string]: unknown;
        };
        impersonatorUserId?: string;
    });
    getActiveOrg(): OrgMemberInfo | undefined;
    getActiveOrgId(): string | undefined;
    getOrg(orgId: string): OrgMemberInfo | undefined;
    getOrgByName(orgName: string): OrgMemberInfo | undefined;
    getOrgs(): OrgMemberInfo[];
    isImpersonating(): boolean;
}
type UseUserLoading = {
    loading: true;
    isLoggedIn: never;
    user: never;
    accessToken: never;
    setActiveOrg: never;
};
type UseUserLoggedIn = {
    loading: false;
    isLoggedIn: true;
    user: User;
    accessToken: string;
    setActiveOrg: (orgId: string) => Promise<User | undefined>;
};
type UseUserNotLoggedIn = {
    loading: false;
    isLoggedIn: false;
    user: undefined;
    accessToken: undefined;
    setActiveOrg: never;
};
type UseUser = UseUserLoading | UseUserLoggedIn | UseUserNotLoggedIn;
declare function useUser(): UseUser;

interface RedirectToSignupOptions {
    postSignupRedirectPath?: string;
    userSignupQueryParameters?: Record<string, string>;
}
interface RedirectToLoginOptions {
    postLoginRedirectPath?: string;
    userSignupQueryParameters?: Record<string, string>;
}
interface RedirectOptions {
    redirectBackToUrl?: string;
}
type AuthProviderProps = {
    authUrl: string;
    reloadOnAuthChange?: boolean;
    children?: React.ReactNode;
};
declare const AuthProvider: (props: AuthProviderProps) => React.JSX.Element;

declare function useHostedPageUrls(): {
    getLoginPageUrl: (opts?: RedirectToLoginOptions | undefined) => string;
    getSignupPageUrl: (opts?: RedirectToSignupOptions | undefined) => string;
    getAccountPageUrl: (opts?: RedirectOptions | undefined) => string;
    getOrgPageUrl: (orgId?: string | undefined, opts?: RedirectOptions | undefined) => string;
    getCreateOrgPageUrl: (opts?: RedirectOptions | undefined) => string;
    getSetupSAMLPageUrl: (orgId: string, opts?: RedirectOptions | undefined) => string;
};

declare function useLogoutFunction(): () => Promise<void>;

declare function useRedirectFunctions(): {
    redirectToSignupPage: (opts?: RedirectToSignupOptions | undefined) => void;
    redirectToLoginPage: (opts?: RedirectToLoginOptions | undefined) => void;
    redirectToAccountPage: (opts?: RedirectOptions | undefined) => void;
    redirectToOrgPage: (orgId?: string | undefined, opts?: RedirectOptions | undefined) => void;
    redirectToCreateOrgPage: (opts?: RedirectOptions | undefined) => void;
    redirectToSetupSAMLPage: (orgId: string, opts?: RedirectOptions | undefined) => void;
};
interface RedirectProps {
    children?: React.ReactNode;
}
declare function RedirectToSignup({ children }: RedirectProps): React.JSX.Element;
declare function RedirectToLogin({ children }: RedirectProps): React.JSX.Element;

declare function useRefreshAuth(): () => Promise<User | undefined>;

export { AuthProvider, AuthProviderProps, OrgIdToOrgMemberInfo, OrgMemberInfo, RedirectProps, RedirectToLogin, RedirectToLoginOptions, RedirectToSignup, RedirectToSignupOptions, UseUser, UseUserLoading, UseUserLoggedIn, UseUserNotLoggedIn, User, UserFromToken, useHostedPageUrls, useLogoutFunction, useRedirectFunctions, useRefreshAuth, useUser };
