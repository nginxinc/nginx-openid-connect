/**
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 * 
 * Copyright (C) 2021 Nginx, Inc.
 */

// Constants for common error message.
var ERR_CFG_VARS  = 'OIDC missing configuration variables: ';
var ERR_AC_TOKEN  = 'OIDC Access Token validation error: ';
var ERR_ID_TOKEN  = 'OIDC ID Token validation error: ';
var ERR_IDP_AUTH  = 'OIDC unexpected response from IdP when sending AuthZ code (HTTP ';
var ERR_TOKEN_RES = 'OIDC AuthZ code sent but token response is not JSON. ';

// Flag to check if there is still valid session cookie. It is used by auth()
// and validateIdToken().
var newSession = false; 

// -------------------------------------------------------------------------- //
//                                                                            //
//           1. Export Functions: Called By `oidc_server.conf`.               //
//                                                                            //
// -------------------------------------------------------------------------- //
export default {auth, codeExchange, validateIdToken, logout, validateAccessToken};

// Start OIDC with either intializing new session or refershing token:
//
// 1. Initialize new session:
//    - Check all necessary configuration variables (referenced only by NJS).
//    - Redirect client to the IdP login page w/ the cookies we need for state.
//
// 2. Refresh ID / access token:
//    - Pass the refresh token to the /_refresh location so that it can be
//      proxied to the IdP in exchange for a new id_token and access_token.
//
function auth(req) {
    if (!req.variables.refresh_token || req.variables.refresh_token == '-') {
        initNewSession(req);
        return;
    }
    refershToken(req);
}

// Request OIDC token, and handle IDP response (error or successful token).
// This function is called by the IdP after successful authentication:
//
// 1. Request OIDC token:
//    - http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
//    - Pass the AuthZ code to the /_token location so that it can be proxied to
//      the IdP in exchange for a JWT.
//
// 2. Handle IDP response:
//   1) Error Response:
//    - https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
//
//   2) Successful Token Response:
//    - https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
//
function codeExchange(req) {
    if (!isValidAuthZCode(req)) {
        return
    }
    req.subrequest('/_token', idpClientAuth(req),
        function(res) {
            var isErr = handleTokenErrorResponse(req, res)
            if (isErr) {
                return
            }
            handleSuccessfulTokenResponse(req, res)
        }
    );
}

// -------------------------------------------------------------------------- //
//                                                                            //
//                          2. Common Functions                               //
//                                                                            //
// -------------------------------------------------------------------------- //

// Initialize new session.
// - Check all necessary configuration variables (referenced only by NJS).
// - redirect the client to the IdP login page w/ the cookies we need for state.
function initNewSession(req) {
    newSession = true;

    var configs = ['authz_endpoint', 'scopes', 'hmac_key', 'cookie_flags'];
    var missingConfig = [];
    for (var i in configs) {
        var oidcCfg = req.variables['oidc_' + configs[i]]
        if (!oidcCfg || oidcCfg == '') {
            missingConfig.push(configs[i]);
        }
    }
    if (missingConfig.length) {
        req.error(ERR_CFG_VARS + '$oidc_' + missingConfig.join(' $oidc_'));
        req.return(500, r.variables.internal_error_message);
        return;
    }
    req.return(302, req.variables.oidc_authz_endpoint + getAuthZArgs(req));
}

// Handle error response regarding the referesh token received from IDP.
// - If the Refresh Request is invalid or unauthorized, the AuthZ Server
//   returns the Token Error Response as defined in OAuth 2.0 [RFC6749].
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse
function handleRefershErrorResponse(req, res) {
    var msg = "OIDC refresh failure";
    switch(res.status) {
        case 504:
            msg += ", timeout waiting for IdP";
            break;
        case 400:
            try {
                var errset = JSON.parse(res.responseBody);
                msg += ": " + errset.error + " " + errset.error_description;
            } catch (e) {
                msg += ": " + res.responseBody;
            }
            break;
        default:
            msg += " "  + res.status;
    }
    req.error(msg);
    clearRefreshTokenAndReturnErr(req);
}

// Clear refersh token, and respond token error.
function clearRefreshTokenAndReturnErr(r) {
    r.variables.refresh_token = "-";
    r.return(302, r.variables.request_uri);
}

// Handle successful response regarding the referesh token.
//
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
// - Upon successful validation of the Refresh Token, the response body is the
//   Token Response of Section 3.1.3.3 except that it might not contain an id_token.
// - Successful Token Response except that it might not contain an id_token.
//
function handleSuccessfulRefreshResponse(r, tokenset) {
    if (!tokenset.id_token) {
        r.error("OIDC refresh response did not include id_token");
        if (tokenset.error) {
            r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
        }
        clearRefreshTokenAndReturnErr(r);
        return;
    }

    // Send the new ID Token to auth_jwt location for validation
    r.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
        function(res) {
            if (res.status != 204) {
                clearRefreshTokenAndReturnErr(r);
                return;
            }

            // ID Token is valid, update keyval
            r.log("OIDC refresh success, updating id_token for " + r.variables.cookie_auth_token);
            r.variables.session_jwt = tokenset.id_token; // Update key-value store

            // Update refresh token (if we got a new one)
            if (r.variables.refresh_token != tokenset.refresh_token) {
                r.log("OIDC replacing previous refresh token (" + r.variables.refresh_token + ") with new value: " + tokenset.refresh_token);
                r.variables.refresh_token = tokenset.refresh_token; // Update key-value store
            }

            delete r.headersOut["WWW-Authenticate"]; // Remove evidence of original failed auth_jwt
            r.internalRedirect(r.variables.request_uri); // Continue processing original request
        }
    );
}

// Pass the refresh token to the /_refresh location so that it can be proxied to
// the IdP in exchange for a new id_token and access_token.
//
// 1. Request refresh token:
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
// - To refresh an Access Token, the Client MUST authenticate to the Token
//   Endpoint using the authentication method registered for its client_id.
//
// 2. Handle IDP response(error or successful refresh token):
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
//
function refershToken(r) {
    r.subrequest("/_refresh", "token=" + r.variables.refresh_token, respHandler);
    function respHandler(res) {
        if (res.status != 200) {
            handleRefershErrorResponse(r, res);
            return;
        }
        try {
            var tokenset = JSON.parse(res.responseBody);
            handleSuccessfulRefreshResponse(r, tokenset);
        } catch (e) {
            clearRefreshTokenAndReturnErr(r);
        }
    }
}

// Handle error response regarding the token received from IDP token endpoint:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
// - If the Token Request is invalid or unauthorized, the Authorization Server
//   constructs the error response.
// - The HTTP response body uses the application/json media type with HTTP 
//   response code of 400.
//
function handleTokenErrorResponse(req, res) {
    var isErr = true
    if (res.status == 504) {
        req.error('OIDC timeout connecting to IdP when sending AuthZ code');
        req.return(504);
        return isErr;
    }
    if (res.status != 200) {
        try {
            var errset = JSON.parse(res.responseBody);
            if (errset.error) {
                req.error('OIDC error from IdP when sending AuthZ code: ' +
                    errset.error + ', ' + errset.error_description);
            } else {
                req.error(ERR_IDP_AUTH + res.status + '). ' + res.responseBody);
            }
        } catch (e) {
            req.error(ERR_IDP_AUTH + res.status + '). ' + res.responseBody);
        }
        req.return(502);
        return isErr;
    }
    return !isErr;
}

// Handle tokens after getting successful token response from the IdP:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
// - After receiving and validating a valid and authorized Token Request from
//   the Client, the Authorization Server returns a successful response that 
//   includes an ID Token and an Access Token.
//
function handleSuccessfulTokenResponse(r, res) {
    try {
        var tokenset = JSON.parse(res.responseBody);
        if (tokenset.error) {
            r.error('OIDC ' + tokenset.error + ' ' + tokenset.error_description);
            r.return(500);
            return;
        }

        // Send the ID Token to auth_jwt location for validation
        r.subrequest('/_id_token_validation', 'token=' + tokenset.id_token,
            function(res) {
                if (res.status != 204) {
                    r.return(500); // validateIdToken() will log errors
                    return;
                }

                // If the response includes a refresh token then store it
                if (tokenset.refresh_token) {
                    r.variables.new_refresh = tokenset.refresh_token; // Create key-value store entry
                    r.log('OIDC refresh token stored');
                } else {
                    r.warn('OIDC no refresh token');
                }

                // Add opaque token to keyval session store
                r.log('OIDC success, creating session ' + r.variables.request_id);
                r.variables.new_session = tokenset.id_token;        // Create key-value store entry
                r.variables.new_access_token = tokenset.access_token;
                r.headersOut['Set-Cookie'] = 'auth_token=' + r.variables.request_id + '; ' + r.variables.oidc_cookie_flags;
                r.return(302, r.variables.redirect_base + r.variables.cookie_auth_redir);
            }
        );
    } catch (e) {
        r.error(ERR_TOKEN_RES + res.responseBody);
        r.return(502);
    }
}

function validateIdToken(r) {
    // Check mandatory claims, and 'aud' is separately checked.
    var required_claims = ['iat', 'iss', 'sub'];
    var missing_claims = [];
    for (var i in required_claims) {
        if (r.variables['jwt_claim_' + required_claims[i]].length == 0 ) {
            missing_claims.push(required_claims[i]);
        }
    }
    if (r.variables.jwt_audience.length == 0) missing_claims.push('aud');
    if (missing_claims.length) {
        r.error(ERR_ID_TOKEN + 'missing claim(s) ' + missing_claims.join(' '));
        r.return(403);
        return;
    }
    var validToken = true;

    // Check iat is a positive integer
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error(ERR_ID_TOKEN + 'iat claim is not a valid number');
        validToken = false;
    }

    // Audience matching
    var aud = r.variables.jwt_audience.split(',');
    if (!aud.includes(r.variables.oidc_client)) {
        r.error(ERR_ID_TOKEN + 'aud claim (' + r.variables.jwt_audience +
            ') does not include configured $oidc_client (' + 
            r.variables.oidc_client + ')');
        validToken = false;
    }

    // If we receive a nonce in the ID Token then we will use the auth_nonce cookies
    // to check that the JWT can be validated as being directly related to the
    // original request by this client. This mitigates against token replay attacks.
    if (newSession) {
        var client_nonce_hash = '';
        if (r.variables.cookie_auth_nonce) {
            var c = require('crypto');
            var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(r.variables.cookie_auth_nonce);
            client_nonce_hash = h.digest('base64url');
        }
        if (r.variables.jwt_claim_nonce != client_nonce_hash) {
            r.error('OIDC ID Token validation error: nonce from token (' + r.variables.jwt_claim_nonce + ') does not match client (' + client_nonce_hash + ')');
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
    r.log('OIDC logout for ' + r.variables.cookie_auth_token);
    r.variables.session_jwt   = '-';
    r.variables.access_token  = '-';
    r.variables.refresh_token = '-';
    r.return(302, r.variables.oidc_logout_redirect);
}

function getAuthZArgs(r) {
    // Choose a nonce for this flow for the client, and hash it for the IdP
    var noncePlain = r.variables.request_id;
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(noncePlain);
    var nonceHash = h.digest('base64url');
    var authZArgs = '?response_type=code&scope=' + r.variables.oidc_scopes + '&client_id=' + r.variables.oidc_client + '&redirect_uri='+ r.variables.redirect_base + r.variables.redir_location + '&nonce=' + nonceHash;

    r.headersOut['Set-Cookie'] = [
        'auth_redir=' + r.variables.request_uri + '; ' + r.variables.oidc_cookie_flags,
        'auth_nonce=' + noncePlain + '; ' + r.variables.oidc_cookie_flags
    ];

    if ( r.variables.oidc_pkce_enable == 1 ) {
        var pkce_code_verifier  = c.createHmac('sha256', r.variables.oidc_hmac_key).update(String(Math.random())).digest('hex');
        r.variables.pkce_id     = c.createHash('sha256').update(String(Math.random())).digest('base64url');
        var pkce_code_challenge = c.createHash('sha256').update(pkce_code_verifier).digest('base64url');
        r.variables.pkce_code_verifier = pkce_code_verifier;

        authZArgs += '&code_challenge_method=S256&code_challenge=' + pkce_code_challenge + '&state=' + r.variables.pkce_id;
    } else {
        authZArgs += '&state=0';
    }
    return authZArgs;
}

function idpClientAuth(r) {
    // If PKCE is enabled we have to use the code_verifier
    if ( r.variables.oidc_pkce_enable == 1 ) {
        r.variables.pkce_id = r.variables.arg_state;
        return 'code=' + r.variables.arg_code + '&code_verifier=' + r.variables.pkce_code_verifier;
    } else {
        return 'code=' + r.variables.arg_code + '&client_secret=' + r.variables.oidc_client_secret;
    }   
}

function validateAccessToken(r) {
    // Check mandatory claims
    var required_claims = ["iat", "iss", "sub"];
    var missing_claims  = [];
    for (var i in required_claims) {
        if (r.variables["jwt_claim_" + required_claims[i]].length == 0 ) {
            missing_claims.push(required_claims[i]);
            r.log("### missing claims " + required_claims[i])
        }
        r.log("### claims " + r.variables["jwt_claim_" + required_claims[i]])
    }
    if (r.variables.jwt_audience.length == 0) missing_claims.push("aud");
    if (missing_claims.length) {
        r.error(ERR_AC_TOKEN + "missing claim(s) " + missing_claims.join(" "));
        r.return(403);
        return;
    }
    var validToken = true;

    // Check iat is a positive integer
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error(ERR_AC_TOKEN + "iat claim is not a valid number");
        validToken = false;
    }

    // If we receive a nonce in the Access Token then we will use the auth_nonce
    // cookies to check that the JWT can be validated as being directly related 
    // to the original request by this client. 
    // 
    // This mitigates against token replay attacks.
    if (newSession) {
        var client_nonce_hash = "";
        if (r.variables.cookie_auth_nonce) {
            var c = require('crypto');
            var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(r.variables.cookie_auth_nonce);
            client_nonce_hash = h.digest('base64url');
        }
        if (r.variables.jwt_claim_nonce != client_nonce_hash) {
            r.error(ERR_AC_TOKEN + "nonce from token (" + r.variables.jwt_claim_nonce + ") does not match client (" + client_nonce_hash + ")");
            validToken = false;
        }
    }

    if (validToken) {
        r.return(204);
    } else {
        r.return(403);
    }
}

// Validate authorization code if it is correctly received from the IdP.
function isValidAuthZCode(r) {
    if (r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error('OIDC error receiving AuthZ code from IdP: ' +
                r.variables.arg_error_description);
        } else {
            r.error('OIDC expected AuthZ code from IdP but received: ' + r.uri);
        }
        r.return(502);
        return false;
    }
    return true;
}
