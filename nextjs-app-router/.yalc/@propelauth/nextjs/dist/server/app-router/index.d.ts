import { NextRequest } from 'next/server.js';

declare class UnauthorizedException extends Error {
    readonly message: string;
    readonly status: number;
    constructor(message: string);
}
declare class ConfigurationException extends Error {
    readonly message: string;
    readonly status: number;
    constructor(message: string);
}

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

type RedirectOptions = {
    returnToPath: string;
    returnToCurrentPath?: never;
} | {
    returnToPath?: never;
    returnToCurrentPath: boolean;
};
declare function getUserOrRedirect(redirectOptions?: RedirectOptions): Promise<UserFromToken>;
declare function getUser(): Promise<UserFromToken | undefined>;
declare function getAccessToken(): string | undefined;
declare function authMiddleware(req: NextRequest): Promise<Response>;
type RouteHandlerArgs = {
    postLoginRedirectPathFn?: (req: NextRequest) => string;
    getDefaultActiveOrgId?: (req: NextRequest, user: UserFromToken) => string | undefined;
};
declare function getRouteHandlers(args?: RouteHandlerArgs): {
    getRouteHandler: (req: NextRequest, { params }: {
        params: {
            slug: string;
        };
    }) => Response | Promise<Response>;
    postRouteHandler: (req: NextRequest, { params }: {
        params: {
            slug: string;
        };
    }) => Response | Promise<Response>;
};
declare function getCurrentUrl(): string | undefined;

export { ConfigurationException, RedirectOptions, RouteHandlerArgs, UnauthorizedException, authMiddleware, getAccessToken, getCurrentUrl, getRouteHandlers, getUser, getUserOrRedirect };
