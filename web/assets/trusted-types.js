/*
 * The CSP requires Trusted Types for script sinks. Only this named policy is
 * allowed, and it accepts same-origin URLs under /app/ so a compromised DOM
 * string cannot point the worker loader at another origin.
 */

const POLICY_NAME = 'mng-ui';
const SCOPE_PREFIX = '/app/';

function policy() {
  if (window.__mngTrustedTypesPolicy) return window.__mngTrustedTypesPolicy;
  if (!window.trustedTypes) return null;
  window.__mngTrustedTypesPolicy = window.trustedTypes.createPolicy(POLICY_NAME, {
    createScriptURL(value) {
      const url = new URL(value, window.location.href);
      if (url.origin !== window.location.origin) {
        throw new TypeError('cross-origin script URL blocked');
      }
      if (!url.pathname.startsWith(SCOPE_PREFIX)) {
        throw new TypeError('script URL outside /app/ blocked');
      }
      return url.href;
    },
  });
  return window.__mngTrustedTypesPolicy;
}

export function trustedScriptUrl(value) {
  const active = policy();
  return active ? active.createScriptURL(value) : value;
}
