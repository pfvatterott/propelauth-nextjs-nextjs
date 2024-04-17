"use client";
var __defProp = Object.defineProperty;
var __defProps = Object.defineProperties;
var __getOwnPropDescs = Object.getOwnPropertyDescriptors;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp.call(b, prop))
      __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(b)) {
      if (__propIsEnum.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps = (a, b) => __defProps(a, __getOwnPropDescs(b));
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

// src/client/AuthProvider.tsx
import React, { useCallback, useEffect, useReducer } from "react";

// src/client/utils.ts
var USER_INFO_KEY = "__PROPEL_AUTH_USER_INFO";
function hasWindow() {
  return typeof window !== "undefined";
}
function saveUserToLocalStorage(user) {
  if (user) {
    localStorage.setItem(USER_INFO_KEY, JSON.stringify(user));
  } else {
    localStorage.setItem(USER_INFO_KEY, "{}");
  }
}
function doesLocalStorageMatch(newValue, user) {
  if (!newValue) {
    return false;
  } else if (!user) {
    return newValue === "{}";
  }
  const parsed = JSON.parse(newValue);
  if (!parsed) {
    return false;
  }
  return isEqual(parsed, user);
}
function isEqual(a, b) {
  if (typeof a !== typeof b) {
    return false;
  }
  if (Array.isArray(a) !== Array.isArray(b)) {
    return false;
  }
  if (Array.isArray(a)) {
    const aArray = a;
    const bArray = b;
    if (aArray.length !== bArray.length) {
      return false;
    }
    for (let i = 0; i < aArray.length; i++) {
      if (!isEqual(aArray[i], bArray[i])) {
        return false;
      }
    }
    return true;
  }
  if (typeof a === "object") {
    const aKeys = Object.keys(a);
    const bKeys = Object.keys(b);
    if (aKeys.length !== bKeys.length) {
      return false;
    }
    for (const key of aKeys) {
      if (!isEqual(a[key], b[key])) {
        return false;
      }
    }
    return true;
  } else {
    return a === b;
  }
}

// src/client/AuthProvider.tsx
import { useRouter } from "next/navigation.js";

// src/client/useUser.tsx
import { useContext } from "react";
var User = class {
  constructor({
    userId,
    email,
    emailConfirmed,
    hasPassword,
    username,
    firstName,
    lastName,
    pictureUrl,
    orgIdToOrgMemberInfo,
    activeOrgId,
    mfaEnabled,
    canCreateOrgs,
    updatePasswordRequired,
    createdAt,
    lastActiveAt,
    legacyUserId,
    properties,
    impersonatorUserId
  }) {
    this.userId = userId;
    this.email = email;
    this.emailConfirmed = emailConfirmed;
    this.hasPassword = hasPassword;
    this.username = username;
    this.firstName = firstName;
    this.lastName = lastName;
    this.pictureUrl = pictureUrl;
    this.orgIdToOrgMemberInfo = orgIdToOrgMemberInfo;
    this.activeOrgId = activeOrgId;
    this.mfaEnabled = mfaEnabled;
    this.canCreateOrgs = canCreateOrgs;
    this.updatePasswordRequired = updatePasswordRequired;
    this.createdAt = createdAt;
    this.lastActiveAt = lastActiveAt;
    this.legacyUserId = legacyUserId;
    this.properties = properties;
    this.impersonatorUserId = impersonatorUserId;
  }
  getActiveOrg() {
    if (!this.activeOrgId) {
      return void 0;
    }
    return this.getOrg(this.activeOrgId);
  }
  getActiveOrgId() {
    return this.activeOrgId;
  }
  getOrg(orgId) {
    var _a;
    return (_a = this.orgIdToOrgMemberInfo) == null ? void 0 : _a[orgId];
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
};
function useUser() {
  const context = useContext(AuthContext);
  if (context === void 0) {
    throw new Error("useUser must be used within an AuthProvider");
  }
  const { loading, userAndAccessToken } = context;
  if (loading) {
    return {
      loading: true,
      isLoggedIn: void 0,
      user: void 0,
      accessToken: void 0,
      setActiveOrg: void 0
    };
  } else if (userAndAccessToken.user) {
    return {
      loading: false,
      isLoggedIn: true,
      user: userAndAccessToken.user,
      accessToken: userAndAccessToken.accessToken,
      setActiveOrg: context.setActiveOrg
    };
  } else {
    return {
      loading: false,
      isLoggedIn: false,
      user: void 0,
      accessToken: void 0,
      setActiveOrg: void 0
    };
  }
}

// src/client/AuthProvider.tsx
var AuthContext = React.createContext(void 0);
var initialAuthState = {
  loading: true,
  userAndAccessToken: {
    user: void 0,
    accessToken: void 0
  },
  authChangeDetected: false
};
function authStateReducer(_state, action) {
  const newUserForEqualityChecking = __spreadProps(__spreadValues({}, action.user), { lastActiveAt: void 0 });
  const existingUserForEqualityChecking = __spreadProps(__spreadValues({}, _state.userAndAccessToken.user), { lastActiveAt: void 0 });
  const authChangeDetected = !_state.loading && !isEqual(newUserForEqualityChecking, existingUserForEqualityChecking);
  if (!action.user) {
    return {
      loading: false,
      userAndAccessToken: {
        user: void 0,
        accessToken: void 0
      },
      authChangeDetected
    };
  } else if (_state.loading) {
    return {
      loading: false,
      userAndAccessToken: {
        user: action.user,
        accessToken: action.accessToken
      },
      authChangeDetected
    };
  } else {
    return {
      loading: false,
      userAndAccessToken: {
        user: action.user,
        accessToken: action.accessToken
      },
      authChangeDetected
    };
  }
}
var AuthProvider = (props) => {
  var _a;
  const [authState, dispatchInner] = useReducer(authStateReducer, initialAuthState);
  const router = useRouter();
  const reloadOnAuthChange = (_a = props.reloadOnAuthChange) != null ? _a : true;
  const dispatch = useCallback(
    (action) => {
      dispatchInner(action);
      saveUserToLocalStorage(action.user);
    },
    [dispatchInner]
  );
  useEffect(() => {
    if (reloadOnAuthChange && authState.authChangeDetected) {
      router.refresh();
    }
  }, [authState.authChangeDetected, reloadOnAuthChange, router]);
  useEffect(() => {
    let didCancel = false;
    function refreshAuthInfo2() {
      return __async(this, null, function* () {
        const action = yield apiGetUserInfo();
        if (!didCancel && !action.error) {
          dispatch(action);
        }
      });
    }
    refreshAuthInfo2();
    return () => {
      didCancel = true;
    };
  }, []);
  useEffect(() => {
    let didCancel = false;
    let retryTimer = void 0;
    function clearAndSetRetryTimer() {
      if (retryTimer) {
        clearTimeout(retryTimer);
      }
      retryTimer = setTimeout(refreshToken, 30 * 1e3);
    }
    function refreshToken() {
      return __async(this, null, function* () {
        const action = yield apiGetUserInfo();
        if (didCancel) {
          return;
        }
        if (!action.error) {
          dispatch(action);
        } else if (action.error === "unexpected") {
          clearAndSetRetryTimer();
        }
      });
    }
    function onStorageEvent(event) {
      return __async(this, null, function* () {
        if (event.key === USER_INFO_KEY && !doesLocalStorageMatch(event.newValue, authState.userAndAccessToken.user)) {
          yield refreshToken();
        }
      });
    }
    const interval = setInterval(refreshToken, 5 * 60 * 1e3);
    if (hasWindow()) {
      window.addEventListener("storage", onStorageEvent);
      window.addEventListener("online", refreshToken);
      window.addEventListener("focus", refreshToken);
    }
    return () => {
      didCancel = true;
      clearInterval(interval);
      if (retryTimer) {
        clearTimeout(retryTimer);
      }
      if (hasWindow()) {
        window.removeEventListener("storage", onStorageEvent);
        window.removeEventListener("online", refreshToken);
        window.removeEventListener("focus", refreshToken);
      }
    };
  }, [dispatch, authState.userAndAccessToken.user]);
  const logout = useCallback(() => __async(void 0, null, function* () {
    yield fetch("/api/auth/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "include"
    });
    dispatch({ user: void 0, accessToken: void 0 });
  }), [dispatch]);
  const getLoginPageUrl = (opts) => {
    if (opts == null ? void 0 : opts.postLoginRedirectPath) {
      return `/api/auth/login?return_to_path=${encodeURIComponent(opts.postLoginRedirectPath)}`;
    }
    return "/api/auth/login";
  };
  const getSignupPageUrl = (opts) => {
    if (opts == null ? void 0 : opts.postSignupRedirectPath) {
      return `/api/auth/signup?return_to_path=${encodeURIComponent(opts.postSignupRedirectPath)}`;
    }
    return "/api/auth/signup";
  };
  const getAccountPageUrl = useCallback(
    (opts) => {
      return addReturnToPath(`${props.authUrl}/account`, opts == null ? void 0 : opts.redirectBackToUrl);
    },
    [props.authUrl]
  );
  const getOrgPageUrl = useCallback(
    (orgId, opts) => {
      if (orgId) {
        return addReturnToPath(`${props.authUrl}/org?id=${orgId}`, opts == null ? void 0 : opts.redirectBackToUrl);
      } else {
        return addReturnToPath(`${props.authUrl}/org`, opts == null ? void 0 : opts.redirectBackToUrl);
      }
    },
    [props.authUrl]
  );
  const getCreateOrgPageUrl = useCallback(
    (opts) => {
      return addReturnToPath(`${props.authUrl}/create_org`, opts == null ? void 0 : opts.redirectBackToUrl);
    },
    [props.authUrl]
  );
  const getSetupSAMLPageUrl = useCallback(
    (orgId, opts) => {
      return addReturnToPath(`${props.authUrl}/saml?id=${orgId}`, opts == null ? void 0 : opts.redirectBackToUrl);
    },
    [props.authUrl]
  );
  const redirectTo = (url) => {
    window.location.href = url;
  };
  const redirectToLoginPage = (opts) => redirectTo(getLoginPageUrl(opts));
  const redirectToSignupPage = (opts) => redirectTo(getSignupPageUrl(opts));
  const redirectToAccountPage = (opts) => redirectTo(getAccountPageUrl(opts));
  const redirectToOrgPage = (orgId, opts) => redirectTo(getOrgPageUrl(orgId, opts));
  const redirectToCreateOrgPage = (opts) => redirectTo(getCreateOrgPageUrl(opts));
  const redirectToSetupSAMLPage = (orgId, opts) => redirectTo(getSetupSAMLPageUrl(orgId, opts));
  const refreshAuthInfo = useCallback(() => __async(void 0, null, function* () {
    const action = yield apiGetUserInfo();
    if (action.error) {
      throw new Error("Failed to refresh token");
    } else {
      dispatch(action);
      return action.user;
    }
  }), [dispatch]);
  const setActiveOrg = useCallback(
    (orgId) => __async(void 0, null, function* () {
      const action = yield apiPostSetActiveOrg(orgId);
      if (action.error === "not_in_org") {
        return void 0;
      } else {
        dispatch(action);
        return action.user;
      }
    }),
    [dispatch]
  );
  const value = {
    loading: authState.loading,
    userAndAccessToken: authState.userAndAccessToken,
    logout,
    redirectToLoginPage,
    redirectToSignupPage,
    redirectToAccountPage,
    redirectToOrgPage,
    redirectToCreateOrgPage,
    redirectToSetupSAMLPage,
    getLoginPageUrl,
    getSignupPageUrl,
    getAccountPageUrl,
    getOrgPageUrl,
    getCreateOrgPageUrl,
    getSetupSAMLPageUrl,
    refreshAuthInfo,
    setActiveOrg
  };
  return /* @__PURE__ */ React.createElement(AuthContext.Provider, { value }, props.children);
};
function apiGetUserInfo() {
  return __async(this, null, function* () {
    try {
      const userInfoResponse = yield fetch("/api/auth/userinfo", {
        method: "GET",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "include"
      });
      if (userInfoResponse.ok) {
        const { userinfo, accessToken, impersonatorUserId, activeOrgId } = yield userInfoResponse.json();
        const user = new User({
          userId: userinfo.user_id,
          email: userinfo.email,
          emailConfirmed: userinfo.email_confirmed,
          hasPassword: userinfo.has_password,
          username: userinfo.username,
          firstName: userinfo.first_name,
          lastName: userinfo.last_name,
          pictureUrl: userinfo.picture_url,
          orgIdToOrgMemberInfo: toOrgIdToOrgMemberInfo(userinfo.org_id_to_org_info),
          activeOrgId,
          mfaEnabled: userinfo.mfa_enabled,
          canCreateOrgs: userinfo.can_create_orgs,
          updatePasswordRequired: userinfo.update_password_required,
          createdAt: userinfo.created_at,
          lastActiveAt: userinfo.last_active_at,
          properties: userinfo.properties,
          impersonatorUserId
        });
        return { user, accessToken, error: void 0 };
      } else if (userInfoResponse.status === 401) {
        return { user: void 0, accessToken: void 0, error: void 0 };
      } else {
        console.info("Failed to refresh token", userInfoResponse);
        return { error: "unexpected" };
      }
    } catch (e) {
      console.info("Failed to refresh token", e);
      return { error: "unexpected" };
    }
  });
}
function apiPostSetActiveOrg(orgId) {
  return __async(this, null, function* () {
    try {
      const queryParams = new URLSearchParams({ active_org_id: orgId }).toString();
      const url = `/api/auth/set-active-org?${queryParams}`;
      const userInfoResponse = yield fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "include"
      });
      if (userInfoResponse.ok) {
        const { userinfo, accessToken, impersonatorUserId, activeOrgId } = yield userInfoResponse.json();
        const user = new User({
          userId: userinfo.user_id,
          email: userinfo.email,
          emailConfirmed: userinfo.email_confirmed,
          hasPassword: userinfo.has_password,
          username: userinfo.username,
          firstName: userinfo.first_name,
          lastName: userinfo.last_name,
          pictureUrl: userinfo.picture_url,
          orgIdToOrgMemberInfo: toOrgIdToOrgMemberInfo(userinfo.org_id_to_org_info),
          activeOrgId,
          mfaEnabled: userinfo.mfa_enabled,
          canCreateOrgs: userinfo.can_create_orgs,
          updatePasswordRequired: userinfo.update_password_required,
          createdAt: userinfo.created_at,
          lastActiveAt: userinfo.last_active_at,
          properties: userinfo.properties,
          impersonatorUserId
        });
        return { user, accessToken, error: void 0 };
      } else if (userInfoResponse.status === 401) {
        return { error: "not_in_org" };
      } else {
        console.info("Failed to set active org", userInfoResponse);
      }
    } catch (e) {
      console.info("Failed to set active org", e);
    }
    throw new Error("Failed to set active org");
  });
}
var encodeBase64 = (str) => {
  const encode = window ? window.btoa : btoa;
  return encode(str);
};
var addReturnToPath = (url, returnToPath) => {
  if (!returnToPath) {
    return url;
  }
  let qs = new URLSearchParams();
  qs.set("rt", encodeBase64(returnToPath));
  if (url.includes("?")) {
    return `${url}&${qs.toString()}`;
  } else {
    return `${url}?${qs.toString()}`;
  }
};

// src/client/useHostedPageUrls.tsx
import { useContext as useContext2 } from "react";
function useHostedPageUrls() {
  const context = useContext2(AuthContext);
  if (context === void 0) {
    throw new Error("useHostedPageUrls must be used within an AuthProvider");
  }
  const {
    getLoginPageUrl,
    getSignupPageUrl,
    getAccountPageUrl,
    getOrgPageUrl,
    getCreateOrgPageUrl,
    getSetupSAMLPageUrl
  } = context;
  return {
    getLoginPageUrl,
    getSignupPageUrl,
    getAccountPageUrl,
    getOrgPageUrl,
    getCreateOrgPageUrl,
    getSetupSAMLPageUrl
  };
}

// src/client/useLogoutFunction.ts
import { useContext as useContext3 } from "react";
function useLogoutFunction() {
  const context = useContext3(AuthContext);
  if (context === void 0) {
    throw new Error("useLogoutFunction must be used within an AuthProvider");
  }
  const { logout } = context;
  return logout;
}

// src/client/useRedirectFunctions.tsx
import React2, { useContext as useContext4, useEffect as useEffect2 } from "react";
function useRedirectFunctions() {
  const context = useContext4(AuthContext);
  if (context === void 0) {
    throw new Error("useRedirectFunctions must be used within an AuthProvider");
  }
  const {
    redirectToAccountPage,
    redirectToSignupPage,
    redirectToLoginPage,
    redirectToOrgPage,
    redirectToCreateOrgPage,
    redirectToSetupSAMLPage
  } = context;
  return {
    redirectToSignupPage,
    redirectToLoginPage,
    redirectToAccountPage,
    redirectToOrgPage,
    redirectToCreateOrgPage,
    redirectToSetupSAMLPage
  };
}
function RedirectToSignup({ children }) {
  const { redirectToSignupPage } = useRedirectFunctions();
  useEffect2(() => {
    redirectToSignupPage();
  }, []);
  return /* @__PURE__ */ React2.createElement(React2.Fragment, null, children);
}
function RedirectToLogin({ children }) {
  const { redirectToLoginPage } = useRedirectFunctions();
  useEffect2(() => {
    redirectToLoginPage();
  }, []);
  return /* @__PURE__ */ React2.createElement(React2.Fragment, null, children);
}

// src/client/useRefreshAuth.ts
import { useContext as useContext5 } from "react";
function useRefreshAuth() {
  const context = useContext5(AuthContext);
  if (context === void 0) {
    throw new Error("useRefreshAuth must be used within an AuthProvider");
  }
  const { refreshAuthInfo } = context;
  return refreshAuthInfo;
}
export {
  AuthProvider,
  OrgMemberInfo,
  RedirectToLogin,
  RedirectToSignup,
  User,
  UserFromToken,
  useHostedPageUrls,
  useLogoutFunction,
  useRedirectFunctions,
  useRefreshAuth,
  useUser
};
//# sourceMappingURL=index.mjs.map