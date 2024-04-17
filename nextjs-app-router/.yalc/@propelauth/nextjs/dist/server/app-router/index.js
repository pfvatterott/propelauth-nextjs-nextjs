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

// src/server/app-router-index.ts
var app_router_index_exports = {};
__export(app_router_index_exports, {
  ConfigurationException: () => ConfigurationException,
  UnauthorizedException: () => UnauthorizedException,
  authMiddleware: () => authMiddleware,
  getAccessToken: () => getAccessToken,
  getCurrentUrl: () => getCurrentUrl,
  getRouteHandlers: () => getRouteHandlers,
  getUser: () => getUser,
  getUserOrRedirect: () => getUserOrRedirect
});
module.exports = __toCommonJS(app_router_index_exports);

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

// src/server/app-router.ts
var import_navigation = require("next/navigation.js");
var import_headers = require("next/headers.js");
var import_server = require("next/server.js");

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

// src/server/shared.ts
var jose = __toESM(require("jose"));
var LOGIN_PATH = "/api/auth/login";
var CALLBACK_PATH = "/api/auth/callback";
var USERINFO_PATH = "/api/auth/userinfo";
var LOGOUT_PATH = "/api/auth/logout";
var ACCESS_TOKEN_COOKIE_NAME = "__pa_at";
var REFRESH_TOKEN_COOKIE_NAME = "__pa_rt";
var STATE_COOKIE_NAME = "__pa_state";
var CUSTOM_HEADER_FOR_ACCESS_TOKEN = "x-propelauth-access-token";
var CUSTOM_HEADER_FOR_URL = "x-propelauth-current-url";
var RETURN_TO_PATH_COOKIE_NAME = "__pa_return_to_path";
var COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: "lax",
  secure: true,
  path: "/"
};
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
function getRedirectUri() {
  const redirectUri = process.env.PROPELAUTH_REDIRECT_URI;
  if (!redirectUri) {
    throw new Error("PROPELAUTH_REDIRECT_URI is not set");
  }
  return redirectUri;
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

// src/server/app-router.ts
function getUserOrRedirect(redirectOptions) {
  return __async(this, null, function* () {
    const user = yield getUser();
    if (user) {
      return user;
    } else {
      redirectToLogin(redirectOptions);
      throw new Error("Redirecting to login");
    }
  });
}
function getUser() {
  return __async(this, null, function* () {
    const accessToken = getAccessToken();
    if (accessToken) {
      const user = yield validateAccessTokenOrUndefined(accessToken);
      if (user) {
        return user;
      }
    }
    return void 0;
  });
}
function getAccessToken() {
  var _a;
  return (0, import_headers.headers)().get(CUSTOM_HEADER_FOR_ACCESS_TOKEN) || ((_a = (0, import_headers.cookies)().get(ACCESS_TOKEN_COOKIE_NAME)) == null ? void 0 : _a.value);
}
function authMiddleware(req) {
  return __async(this, null, function* () {
    var _a, _b, _c;
    if (req.headers.has(CUSTOM_HEADER_FOR_ACCESS_TOKEN)) {
      throw new Error(`${CUSTOM_HEADER_FOR_ACCESS_TOKEN} is set which is for internal use only`);
    } else if (req.headers.has(CUSTOM_HEADER_FOR_URL)) {
      throw new Error(`${CUSTOM_HEADER_FOR_URL} is set which is for internal use only`);
    } else if (req.nextUrl.pathname === CALLBACK_PATH || req.nextUrl.pathname === LOGOUT_PATH || req.nextUrl.pathname === USERINFO_PATH) {
      return getNextResponse(req);
    }
    const accessToken = (_a = req.cookies.get(ACCESS_TOKEN_COOKIE_NAME)) == null ? void 0 : _a.value;
    const refreshToken = (_b = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)) == null ? void 0 : _b.value;
    const activeOrgId = (_c = req.cookies.get(ACTIVE_ORG_ID_COOKIE_NAME)) == null ? void 0 : _c.value;
    if (accessToken) {
      const user = yield validateAccessTokenOrUndefined(accessToken);
      if (user) {
        return getNextResponse(req);
      }
    }
    if (refreshToken) {
      const response = yield refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId);
      if (response.error === "unexpected") {
        throw new Error("Unexpected error while refreshing access token");
      } else if (response.error === "unauthorized") {
        const response2 = getNextResponse(req);
        response2.cookies.delete(ACCESS_TOKEN_COOKIE_NAME);
        response2.cookies.delete(REFRESH_TOKEN_COOKIE_NAME);
        return response2;
      } else {
        const nextResponse = getNextResponse(req, response.accessToken);
        nextResponse.cookies.set(ACCESS_TOKEN_COOKIE_NAME, response.accessToken, COOKIE_OPTIONS);
        nextResponse.cookies.set(REFRESH_TOKEN_COOKIE_NAME, response.refreshToken, COOKIE_OPTIONS);
        return nextResponse;
      }
    }
    return getNextResponse(req);
  });
}
function getNextResponse(request, newAccessToken) {
  const headers2 = new Headers(request.headers);
  headers2.set(CUSTOM_HEADER_FOR_URL, request.nextUrl.toString());
  if (newAccessToken) {
    headers2.set(CUSTOM_HEADER_FOR_ACCESS_TOKEN, newAccessToken);
  }
  return import_server.NextResponse.next({
    request: {
      headers: headers2
    }
  });
}
function getRouteHandlers(args) {
  function loginGetHandler(req) {
    return signupOrLoginHandler(req, false);
  }
  function signupGetHandler(req) {
    return signupOrLoginHandler(req, true);
  }
  function signupOrLoginHandler(req, isSignup) {
    const returnToPath = req.nextUrl.searchParams.get("return_to_path");
    const state = randomState();
    const redirectUri = getRedirectUri();
    const authorizeUrlSearchParams = new URLSearchParams({
      redirect_uri: redirectUri,
      state,
      signup: isSignup ? "true" : "false"
    });
    const authorize_url = getAuthUrlOrigin() + "/propelauth/ssr/authorize?" + authorizeUrlSearchParams.toString();
    const headers2 = new Headers();
    headers2.append("Location", authorize_url);
    headers2.append("Set-Cookie", `${STATE_COOKIE_NAME}=${state}; Path=/; HttpOnly; Secure; SameSite=Lax`);
    if (returnToPath) {
      if (returnToPath.startsWith("/")) {
        headers2.append(
          "Set-Cookie",
          `${RETURN_TO_PATH_COOKIE_NAME}=${returnToPath}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
        );
      } else {
        console.warn("return_to_path must start with /");
      }
    }
    return new Response(null, {
      status: 302,
      headers: headers2
    });
  }
  function callbackGetHandler(req) {
    return __async(this, null, function* () {
      var _a, _b, _c;
      const oauthState = (_a = req.cookies.get(STATE_COOKIE_NAME)) == null ? void 0 : _a.value;
      if (!oauthState || oauthState.length !== 64) {
        return new Response(null, { status: 302, headers: { Location: LOGIN_PATH } });
      }
      const queryParams = req.nextUrl.searchParams;
      const state = queryParams.get("state");
      const code = queryParams.get("code");
      if (state !== oauthState) {
        return new Response(null, { status: 302, headers: { Location: LOGIN_PATH } });
      }
      const authUrlOrigin = getAuthUrlOrigin();
      const redirectUri = getRedirectUri();
      const integrationApiKey = getIntegrationApiKey();
      const oauth_token_body = {
        redirect_uri: redirectUri,
        code
      };
      const url = `${authUrlOrigin}/propelauth/ssr/token`;
      const response = yield fetch(url, {
        method: "POST",
        body: JSON.stringify(oauth_token_body),
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + integrationApiKey
        }
      });
      if (response.ok) {
        const data = yield response.json();
        const accessToken = data.access_token;
        const returnToPathFromCookie = (_b = req.cookies.get(RETURN_TO_PATH_COOKIE_NAME)) == null ? void 0 : _b.value;
        const returnToPath = returnToPathFromCookie != null ? returnToPathFromCookie : (args == null ? void 0 : args.postLoginRedirectPathFn) ? args.postLoginRedirectPathFn(req) : "/";
        if (!returnToPath) {
          console.error("postLoginRedirectPathFn returned undefined");
          return new Response("Unexpected error", { status: 500 });
        }
        const currentActiveOrgId = (_c = req.cookies.get(ACTIVE_ORG_ID_COOKIE_NAME)) == null ? void 0 : _c.value;
        const user = yield validateAccessToken(accessToken);
        const isUserInCurrentActiveOrg = !!currentActiveOrgId && !!user.getOrg(currentActiveOrgId);
        let activeOrgId = void 0;
        if (isUserInCurrentActiveOrg) {
          activeOrgId = currentActiveOrgId;
        } else if (args == null ? void 0 : args.getDefaultActiveOrgId) {
          activeOrgId = args.getDefaultActiveOrgId(req, user);
        }
        if (activeOrgId) {
          const response2 = yield refreshTokenWithAccessAndRefreshToken(data.refresh_token, activeOrgId);
          if (response2.error === "unexpected") {
            throw new Error("Unexpected error while setting active org");
          } else if (response2.error === "unauthorized") {
            console.error(
              "Unauthorized error while setting active org. Your user may not have access to this org"
            );
            return new Response("Unauthorized", { status: 401 });
          } else {
            const headers3 = new Headers();
            headers3.append("Location", returnToPath);
            headers3.append(
              "Set-Cookie",
              `${ACCESS_TOKEN_COOKIE_NAME}=${response2.accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
            );
            headers3.append(
              "Set-Cookie",
              `${REFRESH_TOKEN_COOKIE_NAME}=${response2.refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
            );
            headers3.append(
              "Set-Cookie",
              `${ACTIVE_ORG_ID_COOKIE_NAME}=${activeOrgId}; Path=/; HttpOnly; Secure; SameSite=Lax`
            );
            headers3.append(
              "Set-Cookie",
              `${RETURN_TO_PATH_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
            );
            return new Response(null, {
              status: 302,
              headers: headers3
            });
          }
        }
        const headers2 = new Headers();
        headers2.append("Location", returnToPath);
        headers2.append(
          "Set-Cookie",
          `${ACCESS_TOKEN_COOKIE_NAME}=${accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
        );
        headers2.append(
          "Set-Cookie",
          `${REFRESH_TOKEN_COOKIE_NAME}=${data.refresh_token}; Path=/; HttpOnly; Secure; SameSite=Lax`
        );
        headers2.append(
          "Set-Cookie",
          `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        headers2.append(
          "Set-Cookie",
          `${RETURN_TO_PATH_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        return new Response(null, {
          status: 302,
          headers: headers2
        });
      } else if (response.status === 401) {
        console.error(
          "Couldn't finish the login process for this user. This is most likely caused by an incorrect PROPELAUTH_API_KEY."
        );
        return new Response("Unexpected error", { status: 500 });
      } else {
        return new Response("Unexpected error", { status: 500 });
      }
    });
  }
  function userinfoGetHandler(req) {
    return __async(this, null, function* () {
      var _a, _b;
      const oldRefreshToken = (_a = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)) == null ? void 0 : _a.value;
      const activeOrgId = (_b = req.cookies.get(ACTIVE_ORG_ID_COOKIE_NAME)) == null ? void 0 : _b.value;
      if (oldRefreshToken) {
        const refreshResponse = yield refreshTokenWithAccessAndRefreshToken(oldRefreshToken, activeOrgId);
        if (refreshResponse.error === "unexpected") {
          throw new Error("Unexpected error while refreshing access token");
        } else if (refreshResponse.error === "unauthorized") {
          const headers3 = new Headers();
          headers3.append(
            "Set-Cookie",
            `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
          );
          headers3.append(
            "Set-Cookie",
            `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
          );
          headers3.append(
            "Set-Cookie",
            `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
          );
          return new Response("Unauthorized", { status: 401, headers: headers3 });
        }
        const refreshToken = refreshResponse.refreshToken;
        const accessToken = refreshResponse.accessToken;
        const authUrlOrigin = getAuthUrlOrigin();
        const path = `${authUrlOrigin}/propelauth/oauth/userinfo`;
        const response = yield fetch(path, {
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer " + accessToken
          }
        });
        if (response.ok) {
          const userFromToken = yield validateAccessToken(accessToken);
          const data = yield response.json();
          const jsonResponse = {
            userinfo: data,
            accessToken,
            impersonatorUserId: userFromToken.impersonatorUserId,
            activeOrgId
          };
          const headers3 = new Headers();
          headers3.append(
            "Set-Cookie",
            `${ACCESS_TOKEN_COOKIE_NAME}=${accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
          );
          headers3.append(
            "Set-Cookie",
            `${REFRESH_TOKEN_COOKIE_NAME}=${refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
          );
          headers3.append("Content-Type", "application/json");
          return new Response(JSON.stringify(jsonResponse), {
            status: 200,
            headers: headers3
          });
        } else if (response.status === 401) {
          const headers3 = new Headers();
          headers3.append(
            "Set-Cookie",
            `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
          );
          headers3.append(
            "Set-Cookie",
            `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
          );
          headers3.append(
            "Set-Cookie",
            `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
          );
          return new Response(null, {
            status: 401,
            headers: headers3
          });
        } else {
          return new Response(null, { status: 500 });
        }
      }
      const headers2 = new Headers();
      headers2.append("Set-Cookie", `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
      headers2.append("Set-Cookie", `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
      headers2.append("Set-Cookie", `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
      return new Response(null, { status: 401 });
    });
  }
  function logoutGetHandler(req) {
    return __async(this, null, function* () {
      var _a, _b;
      const path = (args == null ? void 0 : args.postLoginRedirectPathFn) ? args.postLoginRedirectPathFn(req) : "/";
      if (!path) {
        console.error("postLoginPathFn returned undefined");
        return new Response("Unexpected error", { status: 500 });
      }
      const refreshToken = (_a = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)) == null ? void 0 : _a.value;
      if (!refreshToken) {
        const headers2 = new Headers();
        headers2.append("Location", path);
        headers2.append(
          "Set-Cookie",
          `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        headers2.append(
          "Set-Cookie",
          `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        headers2.append(
          "Set-Cookie",
          `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        return new Response(null, {
          status: 302,
          headers: headers2
        });
      }
      const activeOrgId = (_b = req.cookies.get(ACTIVE_ORG_ID_COOKIE_NAME)) == null ? void 0 : _b.value;
      const refreshResponse = yield refreshTokenWithAccessAndRefreshToken(refreshToken, activeOrgId);
      if (refreshResponse.error === "unexpected") {
        console.error("Unexpected error while refreshing access token");
        return new Response("Unexpected error", { status: 500 });
      } else if (refreshResponse.error === "unauthorized") {
        const headers2 = new Headers();
        headers2.append("Location", path);
        headers2.append(
          "Set-Cookie",
          `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        headers2.append(
          "Set-Cookie",
          `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        headers2.append(
          "Set-Cookie",
          `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        return new Response(null, {
          status: 302,
          headers: headers2
        });
      } else {
        const headers2 = new Headers();
        headers2.append("Location", path);
        return new Response(null, {
          status: 302,
          headers: headers2
        });
      }
    });
  }
  function logoutPostHandler(req) {
    return __async(this, null, function* () {
      var _a;
      const refreshToken = (_a = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)) == null ? void 0 : _a.value;
      if (!refreshToken) {
        const headers3 = new Headers();
        headers3.append(
          "Set-Cookie",
          `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        headers3.append(
          "Set-Cookie",
          `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        headers3.append(
          "Set-Cookie",
          `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        return new Response(null, { status: 200, headers: headers3 });
      }
      const authUrlOrigin = getAuthUrlOrigin();
      const integrationApiKey = getIntegrationApiKey();
      const logoutBody = { refresh_token: refreshToken };
      const url = `${authUrlOrigin}/api/backend/v1/logout`;
      const response = yield fetch(url, {
        method: "POST",
        body: JSON.stringify(logoutBody),
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + integrationApiKey
        }
      });
      if (!response.ok) {
        console.warn(
          "Unable to logout, clearing cookies and continuing anyway",
          response.status,
          response.statusText
        );
      }
      const headers2 = new Headers();
      headers2.append("Set-Cookie", `${ACCESS_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
      headers2.append("Set-Cookie", `${REFRESH_TOKEN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
      headers2.append("Set-Cookie", `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
      return new Response(null, { status: 200, headers: headers2 });
    });
  }
  function setActiveOrgHandler(req) {
    return __async(this, null, function* () {
      var _a;
      const oldRefreshToken = (_a = req.cookies.get(REFRESH_TOKEN_COOKIE_NAME)) == null ? void 0 : _a.value;
      const activeOrgId = req.nextUrl.searchParams.get("active_org_id");
      if (!oldRefreshToken) {
        const headers2 = new Headers();
        headers2.append(
          "Set-Cookie",
          `${ACTIVE_ORG_ID_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
        );
        return new Response(null, { status: 401, headers: headers2 });
      }
      if (!activeOrgId) {
        return new Response(null, { status: 400 });
      }
      const refreshResponse = yield refreshTokenWithAccessAndRefreshToken(oldRefreshToken, activeOrgId);
      if (refreshResponse.error === "unexpected") {
        throw new Error("Unexpected error while setting active org id");
      } else if (refreshResponse.error === "unauthorized") {
        return new Response("Unauthorized", { status: 401 });
      }
      const refreshToken = refreshResponse.refreshToken;
      const accessToken = refreshResponse.accessToken;
      const authUrlOrigin = getAuthUrlOrigin();
      const path = `${authUrlOrigin}/propelauth/oauth/userinfo`;
      const response = yield fetch(path, {
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + accessToken
        }
      });
      if (response.ok) {
        const userFromToken = yield validateAccessToken(accessToken);
        const data = yield response.json();
        const jsonResponse = {
          userinfo: data,
          accessToken,
          impersonatorUserId: userFromToken.impersonatorUserId,
          activeOrgId
        };
        const headers2 = new Headers();
        headers2.append(
          "Set-Cookie",
          `${ACCESS_TOKEN_COOKIE_NAME}=${accessToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
        );
        headers2.append(
          "Set-Cookie",
          `${REFRESH_TOKEN_COOKIE_NAME}=${refreshToken}; Path=/; HttpOnly; Secure; SameSite=Lax`
        );
        headers2.append(
          "Set-Cookie",
          `${ACTIVE_ORG_ID_COOKIE_NAME}=${activeOrgId}; Path=/; HttpOnly; Secure; SameSite=Lax`
        );
        headers2.append("Content-Type", "application/json");
        return new Response(JSON.stringify(jsonResponse), {
          status: 200,
          headers: headers2
        });
      } else if (response.status === 401) {
        return new Response(null, {
          status: 401
        });
      } else {
        return new Response(null, { status: 500 });
      }
    });
  }
  function getRouteHandler(req, { params }) {
    if (params.slug === "login") {
      return loginGetHandler(req);
    } else if (params.slug === "signup") {
      return signupGetHandler(req);
    } else if (params.slug === "callback") {
      return callbackGetHandler(req);
    } else if (params.slug === "userinfo") {
      return userinfoGetHandler(req);
    } else if (params.slug === "logout") {
      return logoutGetHandler(req);
    } else {
      return new Response("", { status: 404 });
    }
  }
  function postRouteHandler(req, { params }) {
    if (params.slug === "logout") {
      return logoutPostHandler(req);
    } else if (params.slug === "set-active-org") {
      return setActiveOrgHandler(req);
    } else {
      return new Response("", { status: 404 });
    }
  }
  return {
    getRouteHandler,
    postRouteHandler
  };
}
function randomState() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(randomBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function redirectToLogin(redirectOptions) {
  if (!redirectOptions) {
    (0, import_navigation.redirect)(LOGIN_PATH);
  } else if (redirectOptions.returnToPath) {
    const loginPath = LOGIN_PATH + "?return_to_path=" + encodeURI(redirectOptions.returnToPath);
    (0, import_navigation.redirect)(loginPath);
  } else if (redirectOptions.returnToCurrentPath) {
    const encodedPath = getUrlEncodedRedirectPathForCurrentUrl();
    if (encodedPath) {
      const loginPath = LOGIN_PATH + "?return_to_path=" + encodedPath;
      (0, import_navigation.redirect)(loginPath);
    } else {
      console.warn("Could not get current URL to redirect to");
      (0, import_navigation.redirect)(LOGIN_PATH);
    }
  }
}
function getUrlEncodedRedirectPathForCurrentUrl() {
  const url = getCurrentUrl();
  if (!url) {
    return void 0;
  }
  try {
    const urlObj = new URL(url);
    return encodeURIComponent(urlObj.pathname + urlObj.search);
  } catch (e) {
    console.warn("Current URL is not a valid URL");
    return void 0;
  }
}
function getCurrentUrl() {
  const url = (0, import_headers.headers)().get(CUSTOM_HEADER_FOR_URL);
  if (!url) {
    console.warn("Attempting to redirect to the current URL, but we could not find the current URL in the headers. Is the middleware set up?");
    return void 0;
  } else {
    return url;
  }
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  ConfigurationException,
  UnauthorizedException,
  authMiddleware,
  getAccessToken,
  getCurrentUrl,
  getRouteHandlers,
  getUser,
  getUserOrRedirect
});
//# sourceMappingURL=index.js.map