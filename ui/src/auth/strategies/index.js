const local = require('./local');
const ldapauth = require('./ldapauth');
const oauth2 = require('./oauth2auth');

/**
 * @typedef {Object} IAuthentication
 * @property getStrategy {function(ApplyAuthenticationOptions): Strategy}
 * @property getDefaultCookieSecret {function(ApplyAuthenticationOptions): string}
 * @property getCookieValueFromUser {function(Request, {}, ApplyAuthenticationOptions): {}}
 */

/** @type {Object<string, IAuthentication>} */
module.exports = {
  local,
  ldapauth,
  oauth2
};
