"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};

// src/server/pages-index.ts
var pages_index_exports = {};
__export(pages_index_exports, {
  getUserFromApiRouteRequest: () => getUserFromApiRouteRequest,
  getUserFromServerSideProps: () => getUserFromServerSideProps
});
module.exports = __toCommonJS(pages_index_exports);

// src/loginMethod.ts
function toLoginMethod(snake_case) {
  if (!snake_case) {
    return { loginMethod: "unknown" };
  }
  switch (snake_case.login_method) {
    case "password":
      return { loginMethod: "password" };
    case "magic_link":
      return { loginMethod: "magic_link" };
    case "social_sso":
      return { loginMethod: "social_sso", provider: snake_case.provider };
    case "email_confirmation_link":
      return { loginMethod: "email_confirmation_link" };
    case "saml_sso":
      return { loginMethod: "saml_sso", provider: snake_case.provider, orgId: snake_case.org_id };
    case "impersonation":
      return { loginMethod: "impersonation" };
    case "generated_from_backend_api":
      return { loginMethod: "generated_from_backend_api" };
    default:
      return { loginMethod: "unknown" };
  }
}

// src/user.ts
var UserFromToken = class {
  constructor(userId, email, orgIdToOrgMemberInfo, firstName, lastName, username, legacyUserId, impersonatorUserId, properties, activeOrgId, loginMethod) {
    this.userId = userId;
    this.activeOrgId = activeOrgId;
    this.orgIdToOrgMemberInfo = orgIdToOrgMemberInfo;
    this.email = email;
    this.firstName = firstName;
    this.lastName = lastName;
    this.username = username;
    this.legacyUserId = legacyUserId;
    this.impersonatorUserId = impersonatorUserId;
    this.properties = properties;
    this.loginMethod = loginMethod;
  }
  getActiveOrg() {
    if (!this.activeOrgId || !this.orgIdToOrgMemberInfo) {
      return void 0;
    }
    return this.orgIdToOrgMemberInfo[this.activeOrgId];
  }
  getActiveOrgId() {
    return this.activeOrgId;
  }
  getOrg(orgId) {
    if (!this.orgIdToOrgMemberInfo) {
      return void 0;
    }
    return this.orgIdToOrgMemberInfo[orgId];
  }
  getOrgByName(orgName) {
    if (!this.orgIdToOrgMemberInfo) {
      return void 0;
    }
    const urlSafeOrgName = orgName.toLowerCase().replace(/ /g, "-");
    for (const orgId in this.orgIdToOrgMemberInfo) {
      const orgMemberInfo = this.orgIdToOrgMemberInfo[orgId];
      if (orgMemberInfo.urlSafeOrgName === urlSafeOrgName) {
        return orgMemberInfo;
      }
    }
    return void 0;
  }
  getOrgs() {
    if (!this.orgIdToOrgMemberInfo) {
      return [];
    }
    return Object.values(this.orgIdToOrgMemberInfo);
  }
  isImpersonating() {
    return !!this.impersonatorUserId;
  }
  static fromJSON(json) {
    const obj = JSON.parse(json);
    const orgIdToOrgMemberInfo = {};
    for (const orgId in obj.orgIdToOrgMemberInfo) {
      orgIdToOrgMemberInfo[orgId] = OrgMemberInfo.fromJSON(JSON.stringify(obj.orgIdToOrgMemberInfo[orgId]));
    }
    return new UserFromToken(
      obj.userId,
      obj.email,
      orgIdToOrgMemberInfo,
      obj.firstName,
      obj.lastName,
      obj.username,
      obj.legacyUserId,
      obj.impersonatorUserId,
      obj.properties,
      obj.activeOrgId,
      obj.loginMethod
    );
  }
  static fromJwtPayload(payload) {
    let activeOrgId;
    let orgIdToOrgMemberInfo;
    if (payload.org_member_info) {
      activeOrgId = payload.org_member_info.org_id;
      orgIdToOrgMemberInfo = toOrgIdToOrgMemberInfo({ [activeOrgId]: payload.org_member_info });
    } else {
      activeOrgId = void 0;
      orgIdToOrgMemberInfo = toOrgIdToOrgMemberInfo(payload.org_id_to_org_member_info);
    }
    const loginMethod = toLoginMethod(payload.login_method);
    return new UserFromToken(
      payload.user_id,
      payload.email,
      orgIdToOrgMemberInfo,
      payload.first_name,
      payload.last_name,
      payload.username,
      payload.legacy_user_id,
      payload.impersonatorUserId,
      payload.properties,
      activeOrgId,
      loginMethod
    );
  }
};
var OrgMemberInfo = class {
  constructor(orgId, orgName, orgMetadata, urlSafeOrgName, userAssignedRole, userInheritedRolesPlusCurrentRole, userPermissions) {
    this.orgId = orgId;
    this.orgName = orgName;
    this.orgMetadata = orgMetadata;
    this.urlSafeOrgName = urlSafeOrgName;
    this.userAssignedRole = userAssignedRole;
    this.userInheritedRolesPlusCurrentRole = userInheritedRolesPlusCurrentRole;
    this.userPermissions = userPermissions;
  }
  // validation methods
  isRole(role) {
    return this.userAssignedRole === role;
  }
  isAtLeastRole(role) {
    return this.userInheritedRolesPlusCurrentRole.includes(role);
  }
  hasPermission(permission) {
    return this.userPermissions.includes(permission);
  }
  hasAllPermissions(permissions) {
    return permissions.every((permission) => this.hasPermission(permission));
  }
  static fromJSON(json) {
    const obj = JSON.parse(json);
    return new OrgMemberInfo(
      obj.orgId,
      obj.orgName,
      obj.orgMetadata,
      obj.urlSafeOrgName,
      obj.userAssignedRole,
      obj.userInheritedRolesPlusCurrentRole,
      obj.userPermissions
    );
  }
  // getters for the private fields
  get assignedRole() {
    return this.userAssignedRole;
  }
  get inheritedRolesPlusCurrentRole() {
    return this.userInheritedRolesPlusCurrentRole;
  }
  get permissions() {
    return this.userPermissions;
  }
};
function toUser(snake_case) {
  return UserFromToken.fromJwtPayload(snake_case);
}
function toOrgIdToOrgMemberInfo(snake_case) {
  if (snake_case === void 0) {
    return void 0;
  }
  const camelCase = {};
  for (const key of Object.keys(snake_case)) {
    const snakeCaseValue = snake_case[key];
    if (snakeCaseValue) {
      camelCase[key] = new OrgMemberInfo(
        snakeCaseValue.org_id,
        snakeCaseValue.org_name,
        snakeCaseValue.org_metadata,
        snakeCaseValue.url_safe_org_name,
        snakeCaseValue.user_role,
        snakeCaseValue.inherited_user_roles_plus_current_role,
        snakeCaseValue.user_permissions
      );
    }
  }
  return camelCase;
}

// src/server/exceptions.ts
var UnauthorizedException = class extends Error {
  constructor(message) {
    super(message);
    this.message = message;
    this.status = 401;
  }
};
var ConfigurationException = class extends Error {
  constructor(message) {
    super(message);
    this.message = message;
    this.status = 500;
  }
};

// src/server/shared.ts
var jose = __toESM(require("jose"));
var ACCESS_TOKEN_COOKIE_NAME = "__pa_at";
var REFRESH_TOKEN_COOKIE_NAME = "__pa_rt";
function getAuthUrlOrigin() {
  return getAuthUrl().origin;
}
function getAuthUrl() {
  const authUrl = process.env.NEXT_PUBLIC_AUTH_URL;
  if (!authUrl) {
    throw new Error("NEXT_PUBLIC_AUTH_URL is not set");
  }
  return new URL(authUrl);
}
function getIntegrationApiKey() {
  const integrationApiKey = process.env.PROPELAUTH_API_KEY;
  if (!integrationApiKey) {
    throw new Error("PROPELAUTH_API_KEY is not set");
  }
  return integrationApiKey;
}
function getVerifierKey() {
  const verifierKey = process.env.PROPELAUTH_VERIFIER_KEY;
  if (!verifierKey) {
    throw new Error("PROPELAUTH_VERIFIER_KEY is not set");
  }
  return verifierKey.replace(/\\n/g, "\n");
}
function refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId) {
  return __async(this, null, function* () {
    const body = {
      refresh_token: refreshToken
    };
    const queryParams = new URLSearchParams();
    if (activeOrgId) {
      queryParams.set("with_active_org_support", "true");
      queryParams.set("active_org_id", activeOrgId);
    }
    const url = `${getAuthUrlOrigin()}/api/backend/v1/refresh_token?${queryParams.toString()}`;
    const response = yield fetch(url, {
      method: "POST",
      body: JSON.stringify(body),
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + getIntegrationApiKey()
      }
    });
    if (response.ok) {
      const data = yield response.json();
      const newRefreshToken = data.refresh_token;
      const { access_token: accessToken, expires_at_seconds: expiresAtSeconds } = data.access_token;
      return {
        refreshToken: newRefreshToken,
        accessToken,
        error: "none"
      };
    } else if (response.status === 400 || response.status === 401) {
      return { error: "unauthorized" };
    } else {
      return { error: "unexpected" };
    }
  });
}
function validateAccessTokenOrUndefined(accessToken) {
  return __async(this, null, function* () {
    try {
      return yield validateAccessToken(accessToken);
    } catch (err) {
      if (err instanceof ConfigurationException) {
        throw err;
      } else if (err instanceof UnauthorizedException) {
        return void 0;
      } else {
        console.info("Error validating access token", err);
        return void 0;
      }
    }
  });
}
function validateAccessToken(accessToken) {
  return __async(this, null, function* () {
    let publicKey;
    try {
      publicKey = yield jose.importSPKI(getVerifierKey(), "RS256");
    } catch (err) {
      console.error("Verifier key is invalid. Make sure it's specified correctly, including the newlines.", err);
      throw new ConfigurationException("Invalid verifier key");
    }
    if (!accessToken) {
      throw new UnauthorizedException("No access token provided");
    }
    let accessTokenWithoutBearer = accessToken;
    if (accessToken.toLowerCase().startsWith("bearer ")) {
      accessTokenWithoutBearer = accessToken.substring("bearer ".length);
    }
    try {
      const { payload } = yield jose.jwtVerify(accessTokenWithoutBearer, publicKey, {
        issuer: getAuthUrlOrigin(),
        algorithms: ["RS256"]
      });
      return toUser(payload);
    } catch (e) {
      if (e instanceof Error) {
        throw new UnauthorizedException(e.message);
      } else {
        throw new UnauthorizedException("Unable to decode jwt");
      }
    }
  });
}

// src/shared.ts
var ACTIVE_ORG_ID_COOKIE_NAME = "__pa_org_id";

// src/server/pages.ts
function getUserFromServerSideProps(props, forceRefresh = false) {
  return __async(this, null, function* () {
    const accessToken = props.req.cookies[ACCESS_TOKEN_COOKIE_NAME];
    const refreshToken = props.req.cookies[REFRESH_TOKEN_COOKIE_NAME];
    const activeOrgId = props.req.cookies[ACTIVE_ORG_ID_COOKIE_NAME];
    if (accessToken && !forceRefresh) {
      const user = yield validateAccessTokenOrUndefined(accessToken);
      if (user) {
        return user;
      }
    }
    if (refreshToken) {
      const response = yield refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId);
      if (response.error === "unexpected") {
        throw new Error("Unexpected error while refreshing access token");
      } else if (response.error === "unauthorized") {
        props.res.setHeader("Set-Cookie", [
          `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
          `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        ]);
        return void 0;
      } else {
        const user = yield validateAccessToken(response.accessToken);
        props.res.setHeader("Set-Cookie", [
          `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
          `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
        ]);
        return user;
      }
    }
    return void 0;
  });
}
function getUserFromApiRouteRequest(req, res, forceRefresh = false) {
  return __async(this, null, function* () {
    const accessToken = req.cookies[ACCESS_TOKEN_COOKIE_NAME];
    const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_NAME];
    const activeOrgId = req.cookies[ACTIVE_ORG_ID_COOKIE_NAME];
    if (accessToken && !forceRefresh) {
      const user = yield validateAccessTokenOrUndefined(accessToken);
      if (user) {
        return user;
      }
    }
    if (refreshToken) {
      const response = yield refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId);
      if (response.error === "unexpected") {
        throw new Error("Unexpected error while refreshing access token");
      } else if (response.error === "unauthorized") {
        res.setHeader("Set-Cookie", [
          `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
          `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        ]);
        return void 0;
      } else {
        const user = yield validateAccessToken(response.accessToken);
        res.setHeader("Set-Cookie", [
          `${ACCESS_TOKEN_COOKIE_NAME}=${response.accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
          `${REFRESH_TOKEN_COOKIE_NAME}=${response.refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
        ]);
        return user;
      }
    }
    return void 0;
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  getUserFromApiRouteRequest,
  getUserFromServerSideProps
});
//# sourceMappingURL=index.js.map