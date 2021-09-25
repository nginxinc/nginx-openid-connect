/**
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 * 
 * Copyright (C) 2021 Nginx, Inc.
 */

// Constants for common error message. These will be cleaned up.
var ERR_CFG_VARS     = 'OIDC missing configuration variables: ';
var ERR_AC_TOKEN     = 'OIDC Access Token validation error: ';
var ERR_ID_TOKEN     = 'OIDC ID Token validation error: ';
var ERR_IDP_AUTH     = 'OIDC unexpected response from IdP when sending AuthZ code (HTTP ';
var ERR_TOKEN_RES    = 'OIDC AuthZ code sent but token response is not JSON. ';
var MSG_OK_REFRESH_TOKEN      = 'OIDC refresh success, updating id_token for ';
var MSG_REPLACE_REFRESH_TOKEN = 'OIDC replacing previous refresh token (';

// Flag to check if there is still valid session cookie. It is used by auth()
// and validateIdToken().
var newSession = false; 

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *   1. Export Functions: called by `oidc_server.conf` or any location block.  *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
export default {
    auth,
    codeExchange,
    validateIdToken,
    validateAccessToken,
    logout,
    testExtractBearerToken
};

// Start OIDC with either intializing new session or refershing token:
//
// 1. Start IdP authorization:
//  - Check all necessary configuration variables (referenced only by NJS).
//  - Redirect client to the IdP login page w/ the cookies we need for state.
//
// 2. Refresh ID / access token:
//  - Pass the refresh token to the /_refresh location so that it can be
//    proxied to the IdP in exchange for a new id_token and access_token.
//
function auth(r) {
    r.log('### oidc.auth().startIdPAuthZ(), refersh_token: ' + r.variables.refresh_token)
    if (!r.variables.refresh_token || r.variables.refresh_token == '-') {
        startIdPAuthZ(r);
        return;
    }
    r.log('### oidc.auth().refershToken(), refersh_token: ' + r.variables.refresh_token)
    refershToken(r);
}

// Request OIDC token, and handle IDP response (error or successful token).
// This function is called by the IdP after successful authentication:
//
// 1. Request OIDC token:
//  - http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
//  - Pass the AuthZ code to the /_token location so that it can be proxied to
//    the IdP in exchange for a JWT.
//
// 2. Handle IDP response:
//  1) Error Response:
//   - https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
//
//  2) Successful Token Response:
//   - https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
//
function codeExchange(r) {
    r.log('### start codeExchange()...')
    if (!isValidAuthZCode(r)) {
        return
    }
    r.subrequest('/_token', getTokenArgs(r),
        function(res) {
            var isErr = handleTokenErrorResponse(r, res)
            if (isErr) {
                return
            }
            handleSuccessfulTokenResponse(r, res)
        }
    );
}

// Validate ID token which is received from IdP (fresh or refresh token):
//
// - https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// - This function is called by the location of `_id_token_validation` which is
//   called by either OIDC code exchange or refersh token request.
// - The clients MUST validate the ID Token in the Token Response from the IdP.
//
function validateIdToken(r) {
    var missingClaims = []
    if (r.variables.jwt_audience.length == 0) missingClaims.push('aud');
    if (!isValidRequiredClaims(r, ERR_ID_TOKEN, missingClaims)) {
        r.return(403);
        return;
    }
    if (!isValidIatClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    if (!isValidAudClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    if (!isValidNonceClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    r.return(204);
}

// Validate access token:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
// - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation
// - This function is called by the location of `_access_token_validation` which
//   is called by either OIDC code exchange or refersh token request.
// - The 'aud' claim isn't contained in general ID token from Amazon Cognito,
//   although we can add it. Hence, the claim isn't part of this validation.
//
function validateAccessToken(r) {
    var missingClaims = []
    if (!isValidRequiredClaims(r, ERR_AC_TOKEN, missingClaims)) {
        r.return(403);
        return false;
    }
    if (!isValidIatClaim(r, ERR_AC_TOKEN)) {
        r.return(403);
        return false;
    }
    r.return(204);
    return true
}

function logout(r) {
    r.log('OIDC logout for ' + r.variables.cookie_auth_token);
    r.variables.session_jwt   = '-';
    r.variables.access_token  = '-';
    r.variables.refresh_token = '-';
    r.return(302, r.variables.oidc_logout_redirect);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *                   2. Common Functions for OIDC Workflows                    *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Start Identity Provider (IdP) authorization:
//
// - Check all necessary configuration variables (referenced only by NJS).
// - Redirect the client to the IdP login page w/ the cookies we need for state.
//
function startIdPAuthZ(r) {
    newSession = true;

    var configs = ['authz_endpoint', 'scopes', 'hmac_key', 'cookie_flags'];
    var missingConfig = [];
    for (var i in configs) {
        var oidcCfg = r.variables['oidc_' + configs[i]]
        if (!oidcCfg || oidcCfg == '') {
            missingConfig.push(configs[i]);
        }
    }
    if (missingConfig.length) {
        r.error(ERR_CFG_VARS + '$oidc_' + missingConfig.join(' $oidc_'));
        r.return(500, r.variables.internal_error_message);
        return;
    }
    r.return(302, r.variables.oidc_authz_endpoint + getAuthZArgs(r));
}

// Handle error response regarding the referesh token received from IDP:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse
// - If the Refresh Request is invalid or unauthorized, the AuthZ Server returns
//   the Token Error Response as defined in OAuth 2.0 [RFC6749].
//
function handleRefershErrorResponse(r, res) {
    var msg = 'OIDC refresh failure';
    switch(res.status) {
        case 504:
            msg += ', timeout waiting for IdP';
            break;
        case 400:
            try {
                var errset = JSON.parse(res.responseBody);
                msg += ': ' + errset.error + ' ' + errset.error_description;
            } catch (e) {
                msg += ': ' + res.responseBody;
            }
            break;
        default:
            msg += ' '  + res.status;
    }
    r.error(msg);
    clearRefreshTokenAndReturnErr(r);
}

// Clear refersh token, and respond token error.
function clearRefreshTokenAndReturnErr(r) {
    r.variables.refresh_token = '-';
    r.return(302, r.variables.request_uri);
}

// Handle successful response regarding the referesh token:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
// - Upon successful validation of Refresh Token, the response body is the Token
//   Response of Section 3.1.3.3 except that it might not contain an id_token.
// - Successful Token Response except that it might not contain an id_token.
//
function handleSuccessfulRefreshResponse(r, res) {
    try {
        var tokenset = JSON.parse(res.responseBody);
        var isErr = isValidTokenSet(r, tokenset);
        if (isErr) {
            clearRefreshTokenAndReturnErr(r);
            return;
        }

        // Update opaque ID token and access token to key/value store.
        r.variables.session_jwt  = tokenset.id_token;
        r.variables.access_token = tokenset.access_token;

        // Update new refresh token to key/value store if we got a new one.
        r.log(MSG_OK_REFRESH_TOKEN + r.variables.cookie_auth_token);
        if (r.variables.refresh_token != tokenset.refresh_token) {
            r.log(MSG_REPLACE_REFRESH_TOKEN + r.variables.refresh_token + 
                    ') with new value: ' + tokenset.refresh_token);
            r.variables.refresh_token = tokenset.refresh_token;
        }

        // Remove the evidence of original failed `auth_jwt`, and continue to
        // process the original request.
        delete r.headersOut['WWW-Authenticate'];
        r.internalRedirect(r.variables.request_uri);
    } catch (e) {
        clearRefreshTokenAndReturnErr(r);
    }
}

// Pass the refresh token to the /_refresh location so that it can be proxied to
// the IdP in exchange for a new id_token and access_token:
//
// 1. Request refresh token:
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
//  - To refresh an Access Token, the Client MUST authenticate to the Token
//    Endpoint using the authentication method registered for its client_id.
//
// 2. Handle IDP response(error or successful refresh token):
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
//
function refershToken(r) {
    r.subrequest('/_refresh', 'token=' + r.variables.refresh_token, respHandler);
    function respHandler(res) {
        if (res.status != 200) {
            handleRefershErrorResponse(r, res);
            return;
        }
        handleSuccessfulRefreshResponse(r, res);
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
function handleTokenErrorResponse(r, res) {
    var isErr = true
    if (res.status == 504) {
        r.error('OIDC timeout connecting to IdP when sending AuthZ code');
        r.return(504);
        return isErr;
    }
    if (res.status != 200) {
        try {
            var errset = JSON.parse(res.responseBody);
            if (errset.error) {
                r.error('OIDC error from IdP when sending AuthZ code: ' +
                    errset.error + ', ' + errset.error_description);
            } else {
                r.error(ERR_IDP_AUTH + res.status + '). ' + res.responseBody);
            }
        } catch (e) {
            r.error(ERR_IDP_AUTH + res.status + '). ' + res.responseBody);
        }
        r.return(502);
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
        var isErr = isValidTokenSet(r, tokenset);
        if (isErr) {
             r.return(500);
             return;
        }

        // Add opaque ID token and access token to key/value store
        r.variables.new_session      = tokenset.id_token;
        r.variables.new_access_token = tokenset.access_token;

        // Add new refresh token to key/value store
        if (tokenset.refresh_token) {
            r.variables.new_refresh = tokenset.refresh_token;
            r.log('OIDC refresh token stored');
        } else {
            r.warn('OIDC no refresh token');
        }

        // Set cookie with request ID that is the key of each ID/access token,
        // and continue to process the original request.
        r.log('OIDC success, creating session '    + r.variables.request_id);
        r.headersOut['Set-Cookie'] = 'auth_token=' + r.variables.request_id + 
                                     '; ' + r.variables.oidc_cookie_flags;
        r.return(302, r.variables.redirect_base + r.variables.cookie_auth_redir);
    } catch (e) {
        r.error(ERR_TOKEN_RES + res.responseBody);
        r.return(502);
    }
}

// Check if token is valid using `auth_jwt` directives and Node.JS functions:
//
// - ID     token validation: uri('/_id_token_validation'    )
// - Access token validation: uri('/_access_token_validation')
//
function isValidToken(r, uri, token) {
    if (!token) {
        return false
    }
    var isValid = true
    r.subrequest(uri, 'token=' + token, function(res) {
        if (res.status != 204) {
            isValid = false
        }
    });
    return isValid;
}

// Generate cookie and query parameters using the OIDC config in the nginx.conf:
//
// - Both are used when calling the API endpoint of IdP authorization for the
//   first time when starting Open ID Connect handshaking.
// - Choose a nonce for this flow for the client, and hash it for the IdP.
//
function getAuthZArgs(r) {
    var noncePlain = r.variables.request_id;
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(noncePlain);
    var nonceHash   = h.digest('base64url');
    var redirectURI = r.variables.redirect_base + r.variables.redir_location;
    var authZArgs   = '?response_type=code&scope=' + r.variables.oidc_scopes +
                      '&client_id='                + r.variables.oidc_client + 
                      '&redirect_uri='             + redirectURI; + 
                      '&nonce='                    + nonceHash;
    r.log('\n\n##### redirectURI: ' + redirectURI)
    r.log('      - redirect_base : ' + r.variables.redirect_base)
    r.log('      - redir_location: ' + r.variables.redir_location + '\n')
    var cookieFlags = r.variables.oidc_cookie_flags;
    r.headersOut['Set-Cookie'] = [
        'auth_redir=' + r.variables.request_uri + '; ' + cookieFlags,
        'auth_nonce=' + noncePlain + '; ' + cookieFlags
    ];

    if (r.variables.oidc_pkce_enable == 1) {
        var pkce_code_verifier  = c.createHmac('sha256', r.variables.oidc_hmac_key).
                                    update(randomStr()).digest('hex');
        r.variables.pkce_id     = c.createHash('sha256').
                                    update(randomStr()).digest('base64url');
        var pkce_code_challenge = c.createHash('sha256').
                                    update(pkce_code_verifier).digest('base64url');
        r.variables.pkce_code_verifier = pkce_code_verifier;

        authZArgs += '&code_challenge_method=S256&code_challenge=' + 
                     pkce_code_challenge + '&state=' + r.variables.pkce_id;
    } else {
        authZArgs += '&state=0';
    }
    return authZArgs;
}

// Generate and return random string
function randomStr() {
    return String(Math.random())
}

// Set PKCE ID and generate query parameters for OIDC token endpoint:
//
// - If PKCE is enabled, then we have to use the code_verifier.
// - Otherwise, we use client secret.
//
function getTokenArgs(r) {
    if (r.variables.oidc_pkce_enable == 1) {
        r.variables.pkce_id = r.variables.arg_state;
        return 'code='           + r.variables.arg_code + 
               '&code_verifier=' + r.variables.pkce_code_verifier;
    } else {
        return 'code='           + r.variables.arg_code + 
               '&client_secret=' + r.variables.oidc_client_secret;
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

// Validate 'iat' claim to see if it is valid:
//
// - Check if `iat` is a positive integer.
// - TODO if needed:
//   + It can be used to reject tokens that were issued too far away from
//     the current time, limiting the amount of time that nonces need to be
//     stored to prevent attacks. The acceptable range is Client specific.
//
function isValidIatClaim(r, msgPrefix) {
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error(msgPrefix + 'iat claim is not a valid number');
        return false;
    }
    return true;
}

// Validate 'aud (audience)' claim to see if it is valid:
//
// - The client MUST validate that `aud` claim contains its client_id value
//   registered at the Issuer identified by `iss` claim as an audience.
// - The ID Token MUST be rejected if the ID Token does not list the client
//   as a valid audience, or if it contains additional audiences not trusted
//   by the client.
//
function isValidAudClaim(r, msgPrefix) {
    var aud = r.variables.jwt_audience.split(',');
    if (!aud.includes(r.variables.oidc_client)) {
        r.error(msgPrefix + 'aud claim (' + r.variables.jwt_audience +
            ') does not include configured $oidc_client (' + 
            r.variables.oidc_client + ')');
            return false;
    }
    return true;
}

// Validate `nonce` claim to mitigate replay attacks:
//
// - nonce: a string value used to associate a client session & an ID token. 
//   The value is used to mitigate replay attacks and is present only if 
//   passed during the authorization request.
// - If we receive a nonce in the ID Token then we will use the auth_nonce 
//   cookies to check that JWT can be validated as being directly related to
//   the original request by this client. 
function isValidNonceClaim(r, msgPrefix) {
    if (newSession) {
        var clientNonceHash = '';
        if (r.variables.cookie_auth_nonce) {
            var c = require('crypto');
            var h = c.createHmac('sha256', r.variables.oidc_hmac_key).
                        update(r.variables.cookie_auth_nonce);
            clientNonceHash = h.digest('base64url');
        }
        if (r.variables.jwt_claim_nonce != clientNonceHash) {
            r.error(msgPrefix + 'nonce from token (' + 
                r.variables.jwt_claim_nonce + ') does not match client (' + 
                clientNonceHash + ')');
            return false;
        }
    }
    return true;
}

// Validate if received token from the IdP contains mandatory claims:
//
// - For ID     token: 'iat', 'iss', 'sub', 'aud'
// - For Access token: 'iat', 'iss', 'sub'
// - Given the RFC7519, the above claims are OPTIONAL. But, we validate them
//   as required claims for several purposes such as mitigating replay attacks.
//
function isValidRequiredClaims(r, msgPrefix, missingClaims) {
    var required_claims = ['iat', 'iss', 'sub'];
    try {
        for (var i in required_claims) {
            if (r.variables['jwt_claim_' + required_claims[i]].length == 0 ) {
                missingClaims.push(required_claims[i]);
            }
        }
        if (missingClaims.length) {
            r.error(msgPrefix + 'missing claim(s) ' + missingClaims.join(' '));
            return false;
        }
    } catch (e) {
        r.error("required claims or missing claims do not exist.")
        return false
    }
    return true
}

// Check if (fresh or refersh) token set (ID token, access token) is valid.
function isValidTokenSet(r, tokenset) {
    var isErr = true;
    if (tokenset.error) {
        r.error('OIDC ' + tokenset.error + ' ' + tokenset.error_description);
        return isErr;
    }
    if (!tokenset.id_token) {
        r.error('OIDC response did not include id_token');
        return isErr;
    }
    if (!tokenset.access_token) {
        r.error('OIDC response did not include access_token');
        return isErr;
    }
    if (!isValidToken(r, '/_id_token_validation', tokenset.id_token)) {
        // The validateIdToken() logs error so that r.error() isn't used.
        return isErr;
    }
    if (!isValidToken(r, '/_access_token_validation', tokenset.access_token)) {
        // The validateAccessToken() logs error so that r.error() isn't used.
        return isErr;
    }
    return !isErr;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *                      3. Common Functions for Testing                        *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Test for extracting bearer token from the header of API request:
// 
function testExtractBearerToken (r) {
    var msg = `{"uri":"` + r.variables.request_uri + `"`;
    try {
        var authZ = r.headersIn['Authorization'].split(' ');
        if (authZ[0] === 'Bearer') {
            if (!isValidToken(r, '/_access_token_validation', authZ[1])) {
                msg += `, "token": "invalid"}\n`;
                r.return(401, msg);
                return
            } else {
                msg += `, "token": "` + authZ[1] + `"`;
            }
        } else {
            msg += `, "token": "N/A"`;
        }
    } catch (e) {
        msg += `, "authorization in header": "N/A"`;
    }
    var body = msg + '}\n';
    r.return(200, body);
}
