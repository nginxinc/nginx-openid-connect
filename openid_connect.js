/*
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 *
 * Copyright (C) 2020 Nginx, Inc.
 *
 * Note: This uses the oidc_keyval_id as the log session ID.
 * This ID is a considered non-sensitive as:
 *  - It is not directly redeemable for a session.
 *  - It is available in the keyval stores, so already exposed via the Nginx API (when the API is used).
 *    - The keyval stores contain the IdP access and refresh tokens, which must be protected under all circumstances.
 */
const cryptoLib = require('crypto');

var newSession = false; // Used by oidcAuth() and validateIdToken()

export default {auth, codeExchange, generateKeyValIDCurrent, generateKeyValIDRotate, validateIdToken, logout};

function retryOriginalRequest(r) {
    delete r.headersOut["WWW-Authenticate"]; // Remove evidence of original failed auth_jwt
    r.internalRedirect(r.variables.uri + r.variables.is_args + (r.variables.args || ''));
}

// If the ID token has not been synced yet, poll the variable every 100ms until
// get a value or after a timeout.
function waitForSessionSync(r, timeLeft) {
    if (r.variables.session_jwt) {
        retryOriginalRequest(r);
    } else if (timeLeft > 0) {
        setTimeout(waitForSessionSync, 100, r, timeLeft - 100);
    } else {
        auth(r, true);
    }
}

function auth(r, afterSyncCheck) {
    // If a cookie was sent but the ID token is not in the key-value database, wait for the token to be in sync.
    if (r.variables.cookie_auth_token && !r.variables.session_jwt && !afterSyncCheck && r.variables.zone_sync_leeway > 0) {
        waitForSessionSync(r, r.variables.zone_sync_leeway);
        return;
    }

    if (!r.variables.refresh_token || r.variables.refresh_token == "-") {
        newSession = true;

        // Check we have all necessary configuration variables (referenced only by njs)
        var oidcConfigurables = ["authz_endpoint", "scopes", "hmac_key", "cookie_flags"];
        var missingConfig = [];
        for (var i in oidcConfigurables) {
            if (!r.variables["oidc_" + oidcConfigurables[i]] || r.variables["oidc_" + oidcConfigurables[i]] == "") {
                missingConfig.push(oidcConfigurables[i]);
            }
        }
        if (missingConfig.length) {
            r.error("OIDC missing configuration variables: $oidc_" + missingConfig.join(" $oidc_"));
            r.return(500, r.variables.internal_error_message);
            return;
        }
        // Redirect the client to the IdP login page with the cookies we need for state
        r.return(302, r.variables.oidc_authz_endpoint + getAuthZArgs(r));
        return;
    }

    // Pass the refresh token to the /_refresh location so that it can be
    // proxied to the IdP in exchange for a new id_token
    r.subrequest("/_refresh", "token=" + r.variables.refresh_token,
        function(reply) {
            if (reply.status != 200) {
                // Refresh request failed, log the reason
                var error_log = "OIDC refresh failure";
                if (reply.status == 504) {
                    error_log += ", timeout waiting for IdP";
                } else if (reply.status == 400) {
                    try {
                        var errorset = JSON.parse(reply.responseText);
                        error_log += ": " + errorset.error + " " + errorset.error_description;
                    } catch (e) {
                        error_log += ": " + reply.responseText;
                    }
                } else {
                    error_log += " "  + reply.status;
                }
                r.error(error_log);

                // Clear the refresh token, try again
                r.variables.refresh_token = "-";
                r.return(302, r.variables.request_uri);
                return;
            }

            // Refresh request returned 200, check response
            try {
                var tokenset = JSON.parse(reply.responseText);
                if (!tokenset.id_token) {
                    r.error("OIDC refresh response did not include id_token");
                    if (tokenset.error) {
                        r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                    }
                    r.variables.refresh_token = "-";
                    r.return(302, r.variables.request_uri);
                    return;
                }

                // Send the new ID Token to auth_jwt location for validation
                r.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
                    function(reply) {
                        if (reply.status != 204) {
                            r.variables.refresh_token = "-";
                            r.return(302, r.variables.request_uri);
                            return;
                        }

                        // ID Token is valid, update keyval
                        // updateTokens() updates r on error (false return value)
                        if ( updateTokens(r, tokenset) ) {
                            // Success
                            retryOriginalRequest(r); // Continue processing original request
                        }
                    }
                );
            } catch (e) {
                r.variables.refresh_token = "-";
                r.return(302, r.variables.request_uri);
                return;
            }
        }
    );
}

function codeExchange(r) {
    // First check that we received an authorization code from the IdP
    if (r.variables.arg_code == undefined || r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error("OIDC error receiving authorization code from IdP: " + r.variables.arg_error_description);
        } else {
            r.error("OIDC expected authorization code from IdP but received: " + r.uri);
        }
        r.return(502);
        return;
    }

    // Pass the authorization code to the /_token location so that it can be
    // proxied to the IdP in exchange for a JWT
    r.subrequest("/_token",idpClientAuth(r), function(reply) {
            if (reply.status == 504) {
                r.error("OIDC timeout connecting to IdP when sending authorization code");
                r.return(504);
                return;
            }

            if (reply.status != 200) {
                try {
                    var errorset = JSON.parse(reply.responseText);
                    if (errorset.error) {
                        r.error("OIDC error from IdP when sending authorization code: " + errorset.error + ", " + errorset.error_description);
                    } else {
                        r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseText);
                    }
                } catch (e) {
                    r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseText);
                }
                r.return(502);
                return;
            }

            // Code exchange returned 200, check for errors
            try {
                var tokenset = JSON.parse(reply.responseText);
                if (tokenset.error) {
                    r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                    r.return(500);
                    return;
                }

                // Send the ID Token to auth_jwt location for validation
                r.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
                    function(reply) {
                        if (reply.status != 204) {
                            r.return(500); // validateIdToken() will log errors
                            return;
                        }

                        // Token is valid, store it
                        // updateTokens() updates r on error (false return value)
                        if ( updateTokens(r, tokenset) ) {
                            // Success
                            r.return(302, r.variables.redirect_base + decodeURIComponent(r.variables.cookie_auth_redir));
                        }
                    }
                );
            } catch (e) {
                r.error("OIDC authorization code sent but token response is not JSON. " + reply.responseText);
                r.return(502);
            }
        }
    );
}

function validateIdToken(r) {
    // Check mandatory claims
    var required_claims = ["iat", "iss", "sub"]; // aud is checked separately
    var missing_claims = [];
    for (var i in required_claims) {
        if (r.variables["jwt_claim_" + required_claims[i]].length == 0 ) {
            missing_claims.push(required_claims[i]);
        }
    }
    if (r.variables.jwt_audience.length == 0) missing_claims.push("aud");
    if (missing_claims.length) {
        r.error("OIDC ID Token validation error: missing claim(s) " + missing_claims.join(" "));
        r.return(403);
        return;
    }
    var validToken = true;

    // Check iat is a positive integer
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error("OIDC ID Token validation error: iat claim is not a valid number");
        validToken = false;
    }

    // Audience matching
    var aud = r.variables.jwt_audience.split(",");
    if (!aud.includes(r.variables.oidc_client)) {
        r.error("OIDC ID Token validation error: aud claim (" + r.variables.jwt_audience + ") does not include configured $oidc_client (" + r.variables.oidc_client + ")");
        validToken = false;
    }

    // If we receive a nonce in the ID Token then we will use the auth_nonce cookies
    // to check that the JWT can be validated as being directly related to the
    // original request by this client. This mitigates against token replay attacks.
    if (newSession) {
        var client_nonce_hash = "";
        if (r.variables.cookie_auth_nonce) {
            var h = cryptoLib.createHmac('sha256', r.variables.oidc_hmac_key).update(r.variables.cookie_auth_nonce);
            client_nonce_hash = h.digest('base64url');
        }
        if (r.variables.jwt_claim_nonce != client_nonce_hash) {
            r.error("OIDC ID Token validation error: nonce from token (" + r.variables.jwt_claim_nonce + ") does not match client (" + client_nonce_hash + ")");
            validToken = false;
        }
    }

    if (validToken) {
        r.return(204);
    } else {
        r.return(403);
    }
}

function logout(r) {
    r.log("OIDC logout for " + r.variables.oidc_keyval_id_current);
    r.variables.session_jwt   = "-";
    r.variables.access_token  = "-";
    r.variables.refresh_token = "-";
    r.return(302, r.variables.oidc_logout_redirect);
}

function generateID(keyLength) {
    keyLength = keyLength > 20 ? keyLength : 20;
    let buf = Buffer.alloc(keyLength);
    return (crypto.getRandomValues(buf)).toString('hex');
}

// Generates the keyval key for the keyval module stores based on the clientToken argument.
// This hashing is done to generate a keyval key ID unique to the client session but which is not redeemable for a session via the auth_token cookie.
// This is protection against keyval store compromise.
function generateKeyValID(r, clientToken) {
    if ( !clientToken) {
        throw(`Unsuitable clientToken passed: "${clientToken}"`);
    }

    let tokenHash = cryptoLib.createHmac('sha256', r.variables.oidc_hmac_key).update(clientToken);

    let rv = tokenHash.digest('base64url');
    return rv;
}

// Generates the keyval key for the keyval module stores based on the cookie_auth_token passed by the client.
// Intended for the first-pass keyval lookups to look up existing values.
// intended to be called by the js_set directive in Nginx config.
//
// This function will return null if there is no existing session.
// Not intended or safe for setting keyval store pairs.
function generateKeyValIDCurrent(r) {
    // "-" is the "unset" value
    if ( r.variables.cookie_auth_token && r.variables.cookie_auth_token != "-" ) {
        return generateKeyValID(r, r.variables.cookie_auth_token);
    }

    // Return null, which should never be a valid key in the keyval stores (enforced in updateTokens()).
    // Don't return a random ID in case there is a ID collision, that could lead to a user getting the wrong session.
    return null;
}

// Generates a random, new keyval key for the keyval module stores.
// Intended for token update calls *only*.
function generateKeyValIDRotate(r) {
    let clientToken = generateID();

    r.headersOut["Set-Cookie"] = "auth_token=" + clientToken + "; " + r.variables.oidc_cookie_flags;
    return generateKeyValID(r, clientToken);
}

function getAuthZArgs(r) {
    // Choose a nonce for this flow for the client, and hash it for the IdP
    var noncePlain = generateID();
    var h = cryptoLib.createHmac('sha256', r.variables.oidc_hmac_key).update(noncePlain);
    var nonceHash = h.digest('base64url');
    var authZArgs = "?response_type=code&scope=" + r.variables.oidc_scopes + "&client_id=" + r.variables.oidc_client + "&redirect_uri="+ r.variables.redirect_base + r.variables.redir_location + "&nonce=" + nonceHash;

    if (r.variables.oidc_authz_extra_args) {
        authZArgs += "&" + r.variables.oidc_authz_extra_args;
    }

    var encodedRequestUri = encodeURIComponent(r.variables.request_uri);

    r.headersOut['Set-Cookie'] = [
        "auth_redir=" + encodedRequestUri + "; " + r.variables.oidc_cookie_flags,
        "auth_nonce=" + noncePlain + "; " + r.variables.oidc_cookie_flags
    ];

    if ( r.variables.oidc_pkce_enable == 1 ) {
        var pkce_code_verifier = c.createHmac('sha256', r.variables.oidc_hmac_key).update(String(Math.random())).digest('hex');
        r.variables.pkce_id = c.createHash('sha256').update(String(Math.random())).digest('base64url');
        var pkce_code_challenge = c.createHash('sha256').update(pkce_code_verifier).digest('base64url');
        r.variables.pkce_code_verifier = pkce_code_verifier;

        authZArgs += "&code_challenge_method=S256&code_challenge=" + pkce_code_challenge + "&state=" + r.variables.pkce_id;
    } else {
        authZArgs += "&state=0";
    }
    return authZArgs;
}

function idpClientAuth(r) {
    // If PKCE is enabled we have to use the code_verifier
    if ( r.variables.oidc_pkce_enable == 1 ) {
        r.variables.pkce_id = r.variables.arg_state;
        return "code=" + r.variables.arg_code + "&code_verifier=" + r.variables.pkce_code_verifier;
    } else {
        return "code=" + r.variables.arg_code + "&client_secret=" + r.variables.oidc_client_secret;
    }
}

// Performs a update of the token keyval stores from a provided tokenset argument.
// Common codepath for new sessions and refreshes.
// Performs basic fault checking and rotates the client session access token each invocation via an indirect call to generateKeyValIDRotate().
function updateTokens(r, tokenset) {
    try {
        // NOTE: This call to r.variables.oidc_keyval_id_rotate is intended to be the trigger that rotates the client token
        // Rotating the session ID each update is done as it increases security while simultaneously reducing the code complexity
        //   as one set path is valid for both new and refresh operations.
        // Calling r.variables.oidc_keyval_id_rotate calls generateKeyValIDRotate() (via js_set in Nginx config) which sets the auth_token cookie
        r.log(`OIDC success, updating session for ${r.variables.oidc_keyval_id_rotate}`);
        // Sanity check to a void using something falsy like `undefined` for all the token keys,
        //   which would be a terrible bug potentially leading to incorrect sessions being returned.
        if ( ! r.variables.oidc_keyval_id_rotate ) {
            // This is a bug when this codepath is triggered. r.variables.oidc_keyval_id_rotate should be set.
            r.error("OIDC Session Error: INTERNAL ERROR: Rotate keyval key undefined");
            r.return(500);
            return false;
        }

        // Ensure there isn't an ID collision
        let tokenNames = ["session", "access", "refresh"];
        let currentTokenValues = [r.variables.new_session, r.variables.new_access, r.variables.new_refresh];
        for (var index in tokenNames) {
            if ( currentTokenValues[index] ) {
                r.error(`OIDC Session Error: ${tokenNames[index]} token collision for session ID ${r.variables.oidc_keyval_id_rotate}`);
                r.return(500);
                return false;
            }
        }

        r.variables.new_session = tokenset.id_token;

        if (tokenset.refresh_token) {
            r.variables.new_refresh = tokenset.refresh_token;
            r.log(`New OIDC refresh token stored for session ${r.variables.oidc_keyval_id_rotate}`);
        } else {
            r.variables.new_refresh = "-";
            r.warn(`OIDC no refresh token for session ${r.variables.oidc_keyval_id_rotate}`);
        }

        if (tokenset.access_token) {
            r.variables.new_access_token = tokenset.access_token;
            r.log(`OIDC access token stored for session ${r.variables.oidc_keyval_id_rotate}`);
        } else {
            r.variables.new_access_token = "-";
        }

        if ( r.variables.oidc_keyval_id_current ) {
            // Flush the old tokens
            r.variables.session_jwt = "-";
            r.variables.refresh_token  = "-";
            r.variables.access_token = "-";
        }

        // Set $oidc_keyval_id_current to $oidc_keyval_id_rotate for the refresh flow.
        r.variables.oidc_keyval_id_current = r.variables.oidc_keyval_id_rotate;

        return true;

    } catch (e) {
        r.error(`OIDC Session Error: Failed to update session ID ${r.variables.oidc_keyval_id_rotate}: ${e}`);

        r.variables.new_session = "-";
        r.variables.new_access  = "-";
        r.variables.new_refresh = "-";

        r.return(500);
        return false;
    }
}
