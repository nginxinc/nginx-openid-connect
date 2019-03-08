/*
 * nginScript functions for providing OpenID Connect authorization
 * code flow with NGINX Plus.
 *
 * Copyright (C) 2019 Nginx, Inc.
 */

var auth_token = "";

function oidcCodeExchange(r) {
    // First check that we received an authorization code from the IdP
    if (r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error("OIDC error receiving authorization code from IdP: " + r.variables.arg_error_description);
        } else {
            r.error("OIDC expected authorization code from IdP but received: " + r.variables.uri);
        }
        r.return(502);
        return;
    }

    // Pass the authorization code to the /_token location so that it can be
    // proxied to the IdP in exchange for a JWT
    r.subrequest("/_token", "code=" + r.variables.arg_code,
        function(reply) {
            if (reply.status == 504) {
                r.error("OIDC timeout connecting to IdP when sending authorization code");
                r.return(504);
                return;
            }

            if (reply.status != 200) {
                try {
                    var errorset = JSON.parse(reply.responseBody);
                    if (errorset.error) {
                        r.error("OIDC error from IdP when sending authorization code: " + errorset.error + ", " + errorset.error_description);
                    } else {
                        r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseBody);
                    }
                } catch (e) {
                    r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseBody);
                }
                r.return(502);
                return;
            }

            // Code exchange returned 200, check response
            try {
                var tokenset = JSON.parse(reply.responseBody);
                if (!tokenset[r.variables.oidc_token_type]) {
                    r.error("OIDC received id_token but not " + r.variables.oidc_token_type);
                    if (tokenset.error) {
                        r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                    }
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

                        // ID Token is valid
                        r.log("OIDC success, sending " + r.variables.oidc_token_type);
                        auth_token = tokenset[r.variables.oidc_token_type]; // Export as NGINX variable
                        r.return(302, r.variables.cookie_auth_redir);
                   }
                );
            } catch (e) {
                r.error("OIDC authorization code sent but token response is not JSON. " + reply.status + " " + reply.responseBody);
                r.return(502);
            }
        }
    );
}

function getAuthToken(r) {
    return auth_token;
}

function hashRequestId(r) {
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(r.variables.request_id);
    return h.digest('base64url');
}

function validateIdToken(r) {
    // Check mandatory claims
    var required_claims = ["aud", "iat", "iss", "sub"];
    var missing_claims = [];
    for (var i in required_claims) {
        if (r.variables["jwt_claim_" + required_claims[i]].length == 0 ) {
            missing_claims.push(required_claims[i]);
        }
    }
    if (missing_claims.length) {
        r.error("OIDC ID Token validation error: missing claim(s) " + missing_claims.join(" "));
        r.return(403);
        return;
    }
    var valid_token = true;

    // Check iat is a positive integer
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error("OIDC ID Token validation error: iat claim is not a valid number");
        valid_token = false;
    }

    // Audience matching
    if (r.variables.jwt_claim_aud != r.variables.oidc_client) {
        r.error("OIDC ID Token validation error: aud claim (" + r.variables.jwt_claim_aud + ") does not match $oidc_client");
        valid_token = false;
    }

    // If we receive a nonce in the ID Token then we will use the auth_nonce cookie
    // to check that the JWT can be validated as being directly related to the
    // original request by this client. This mitigates against token replay attacks.
    var client_nonce_hash = "";
    if (r.variables.cookie_auth_nonce) {
        var c = require('crypto');
        var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(r.variables.cookie_auth_nonce);
        client_nonce_hash = h.digest('base64url');
    }
    if (r.variables.jwt_claim_nonce != client_nonce_hash) {
        r.error("OIDC ID Token validation error: nonce mismatch");
        valid_token = false;
    }

    if (valid_token) {
        r.return(204);
    } else {
        r.return(403);
    }
}