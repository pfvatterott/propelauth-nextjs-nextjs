import * as _propelauth_node_apis from '@propelauth/node-apis';
export { AccessToken, AccessTokenCreationException, AddUserToOrgException, AddUserToOrgRequest, ApiKeyCreateException, ApiKeyDeleteException, ApiKeyFetchException, ApiKeyFull, ApiKeyNew, ApiKeyResultPage, ApiKeyUpdateException, ApiKeyUpdateRequest, ApiKeyValidateException, ApiKeyValidation, ApiKeysCreateRequest, ApiKeysQueryRequest, ChangeUserRoleInOrgException, CreateAccessTokenRequest, CreateMagicLinkRequest, CreateOrgException, CreateOrgRequest, CreateUserException, CreateUserRequest, ForbiddenException, MagicLink, MagicLinkCreationException, MigrateUserException, MigrateUserFromExternalSourceRequest, OrgApiKeyValidation, OrgQuery, OrgQueryResponse, PersonalApiKeyValidation, RemoveUserFromOrgException, RemoveUserFromOrgRequest, TokenVerificationMetadata, UnexpectedException, UpdateOrgException, UpdateOrgRequest, UpdateUserEmailException, UpdateUserEmailRequest, UpdateUserMetadataException, UpdateUserMetadataRequest, UpdateUserPasswordException, UpdateUserPasswordRequest, UserNotFoundException, UsersInOrgQuery, UsersPagedResponse, UsersQuery } from '@propelauth/node-apis';

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

declare function validateAccessTokenOrUndefined(accessToken: string | undefined): Promise<UserFromToken | undefined>;
declare function validateAccessToken(accessToken: string | undefined): Promise<UserFromToken>;

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

declare const getPropelAuthApis: () => {
    fetchUserMetadataByUserId: (userId: string, includeOrgs?: boolean | undefined) => Promise<_propelauth_node_apis.UserMetadata | null>;
    fetchUserMetadataByEmail: (email: string, includeOrgs?: boolean | undefined) => Promise<_propelauth_node_apis.UserMetadata | null>;
    fetchUserMetadataByUsername: (username: string, includeOrgs?: boolean | undefined) => Promise<_propelauth_node_apis.UserMetadata | null>;
    fetchBatchUserMetadataByUserIds: (userIds: string[], includeOrgs?: boolean | undefined) => Promise<{
        [userId: string]: _propelauth_node_apis.UserMetadata;
    }>;
    fetchBatchUserMetadataByEmails: (emails: string[], includeOrgs?: boolean | undefined) => Promise<{
        [email: string]: _propelauth_node_apis.UserMetadata;
    }>;
    fetchBatchUserMetadataByUsernames: (usernames: string[], includeOrgs?: boolean | undefined) => Promise<{
        [username: string]: _propelauth_node_apis.UserMetadata;
    }>;
    fetchOrg: (orgId: string) => Promise<_propelauth_node_apis.Org | null>;
    fetchOrgByQuery: (orgQuery: _propelauth_node_apis.OrgQuery) => Promise<_propelauth_node_apis.OrgQueryResponse>;
    fetchUsersByQuery: (usersQuery: _propelauth_node_apis.UsersQuery) => Promise<_propelauth_node_apis.UsersPagedResponse>;
    fetchUsersInOrg: (usersInOrgQuery: _propelauth_node_apis.UsersInOrgQuery) => Promise<_propelauth_node_apis.UsersPagedResponse>;
    createUser: (createUserRequest: _propelauth_node_apis.CreateUserRequest) => Promise<_propelauth_node_apis.User>;
    updateUserMetadata: (userId: string, updateUserMetadataRequest: _propelauth_node_apis.UpdateUserMetadataRequest) => Promise<boolean>;
    updateUserEmail: (userId: string, updateUserEmailRequest: _propelauth_node_apis.UpdateUserEmailRequest) => Promise<boolean>;
    updateUserPassword: (userId: string, updateUserPasswordRequest: _propelauth_node_apis.UpdateUserPasswordRequest) => Promise<boolean>;
    createMagicLink: (createMagicLinkRequest: _propelauth_node_apis.CreateMagicLinkRequest) => Promise<_propelauth_node_apis.MagicLink>;
    createAccessToken: (createAccessTokenRequest: _propelauth_node_apis.CreateAccessTokenRequest) => Promise<_propelauth_node_apis.AccessToken>;
    migrateUserFromExternalSource: (migrateUserFromExternalSourceRequest: _propelauth_node_apis.MigrateUserFromExternalSourceRequest) => Promise<_propelauth_node_apis.User>;
    deleteUser: (userId: string) => Promise<boolean>;
    disableUser: (userId: string) => Promise<boolean>;
    enableUser: (userId: string) => Promise<boolean>;
    disableUser2fa: (userId: string) => Promise<boolean>;
    enableUserCanCreateOrgs: (userId: string) => Promise<boolean>;
    disableUserCanCreateOrgs: (userId: string) => Promise<boolean>;
    createOrg: (createOrgRequest: _propelauth_node_apis.CreateOrgRequest) => Promise<{
        orgId: string;
        name: string;
    }>;
    addUserToOrg: (addUserToOrgRequest: _propelauth_node_apis.AddUserToOrgRequest) => Promise<boolean>;
    changeUserRoleInOrg: (changeUserRoleInOrgRequest: {
        userId: string;
        orgId: string;
        role: string;
    }) => Promise<boolean>;
    removeUserFromOrg: (removeUserFromOrgRequest: _propelauth_node_apis.RemoveUserFromOrgRequest) => Promise<boolean>;
    updateOrg: (updateOrgRequest: _propelauth_node_apis.UpdateOrgRequest) => Promise<boolean>;
    deleteOrg: (orgId: string) => Promise<boolean>;
    allowOrgToSetupSamlConnection: (orgId: string) => Promise<boolean>;
    disallowOrgToSetupSamlConnection: (orgId: string) => Promise<boolean>;
    inviteUserToOrg: (inviteUserToOrgRequest: _propelauth_node_apis.InviteUserToOrgRequest) => Promise<boolean>;
    fetchApiKey: (apiKeyId: string) => Promise<_propelauth_node_apis.ApiKeyFull>;
    fetchCurrentApiKeys: (apiKeyQuery: _propelauth_node_apis.ApiKeysQueryRequest) => Promise<_propelauth_node_apis.ApiKeyResultPage>;
    fetchArchivedApiKeys: (apiKeyQuery: _propelauth_node_apis.ApiKeysQueryRequest) => Promise<_propelauth_node_apis.ApiKeyResultPage>;
    createApiKey: (apiKeyCreate: _propelauth_node_apis.ApiKeysCreateRequest) => Promise<_propelauth_node_apis.ApiKeyNew>;
    updateApiKey: (apiKeyId: string, ApiKeyUpdate: _propelauth_node_apis.ApiKeyUpdateRequest) => Promise<boolean>;
    deleteApiKey: (apiKeyId: string) => Promise<boolean>;
    validateApiKey: (apiKeyToken: string) => Promise<_propelauth_node_apis.ApiKeyValidation>;
    validatePersonalApiKey: (apiKeyToken: string) => Promise<_propelauth_node_apis.PersonalApiKeyValidation>;
    validateOrgApiKey: (apiKeyToken: string) => Promise<_propelauth_node_apis.OrgApiKeyValidation>;
};

export { ConfigurationException, OrgIdToOrgMemberInfo, OrgMemberInfo, UnauthorizedException, UserFromToken, getPropelAuthApis, validateAccessToken, validateAccessTokenOrUndefined };
