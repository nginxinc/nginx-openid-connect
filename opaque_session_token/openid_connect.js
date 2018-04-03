/*
 * nginScript functions for providing OpenID Connect authorization
 * code flow with NGINX Plus.
 *
 * Copyright (C) 2018 Nginx, Inc.
 */

var auth_token = "";

function oidcCodeExchange(req, res) {
    // First check that we received an authorization code from the IdP
    if (req.variables.arg_code.length == 0) {
        if (req.variables.arg_error) {
            req.error("OIDC error receiving authorization code from IdP: " + req.variables.arg_error_description);
        } else {
            req.error("OIDC expected authorization code from IdP but received: " + req.variables.uri);
        }
        res.return(502);
        return;
    }

    // Pass the authorization code to the /_token location so that it can be
    // proxied to the IdP in exchange for a JWT
    req.subrequest("/_token", "code=" + req.variables.arg_code,
        function(reply) {
            if (reply.status == 504) {
                req.error("OIDC timeout connecting to IdP when sending authorization code");
                res.return(504);
                return;
            }

            if (reply.status != 200) {
                try {
                    var errorset = JSON.parse(reply.body);
                    if (errorset.error) {
                        req.error("OIDC error from IdP when sending authorization code: " + errorset.error + ", " + errorset.error_description);
                    } else {
                        req.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.body);
                    }
                } catch (e) {
                    req.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.body);
                }
                res.return(502);
                return;
            }

            // Code exchange returned 200, check response
            try {
                // Send the ID Token to auth_jwt location for validation
                var tokenset = JSON.parse(reply.body);
                req.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
                    function(reply) {
                        if (reply.status != 204) {
                            res.return(500); // validateIdToken() will log errors
                            return;
                        }

                        // ID Token is valid
                        req.subrequest("/_create_session", "key=" + req.variables.request_id + "&val=" + tokenset.id_token,
                            function(reply) {
                                if (reply.status != 201) {
                                    req.error("OIDC error creating session in keyval (" + reply.status + ") " + reply.body);
                                    res.return(500);
                                    return;
                                }

                                // Session created
                                req.log("OIDC success, creating session " + req.variables.request_id);
                                auth_token = req.variables.request_id; // Export as NGINX variable
                                res.return(302, req.variables.cookie_auth_redir);
                             }
                        );
                   }
                );
            } catch (e) {
                req.error("OIDC authorization code sent but token response is not JSON. " + reply.body);
                res.return(502);
            }
        }
    );
}

function getAuthToken(req,res) {
    return auth_token;
}

function hashRequestId(req) {
    var c = require('crypto');
    var h = c.createHmac('sha256', req.variables.oidc_hmac_key).update(req.variables.request_id);
    return h.digest('base64url');
}

function validateIdToken(req,res) {
    // Check mandatory claims
    var required_claims = ["aud", "iat", "iss", "sub"];
    var missing_claims = [];
    for (var i in required_claims) {
        if (req.variables["jwt_claim_" + required_claims[i]].length == 0 ) {
            missing_claims.push(required_claims[i]);
        }
    }
    if (missing_claims.length) {
        req.error("OIDC ID Token validation error: missing claim(s) " + missing_claims.join(" "));
        res.return(403);
        return;
    }
    var valid_token = true;

    // Check iat is a number
    var iat = Math.floor(Number(req.variables.jwt_claim_iat));
    if (String(iat) != req.variables.jwt_claim_iat || iat < 1) {
        req.error("OIDC ID Token validation error: iat claim is not a valid number");
        valid_token = false;
    }

    // Check iss relates to $oidc_authz_endpoint
    if (!req.variables.oidc_authz_endpoint.startsWith(req.variables.jwt_claim_iss)) {
        req.error("OIDC ID Token validation error: iss claim (" + req.variables.jwt_claim_iss  + ") is not found in $oidc_authz_endpoint");
        valid_token = false;
    }

    // Audience matching
    if (req.variables.jwt_claim_aud != req.variables.oidc_client) {
        req.error("OIDC ID Token validation error: aud claim (" + req.variables.jwt_claim_aud + ") does not match $oidc_client");
        valid_token = false;
    }

    // If we receive a nonce in the ID Token then we will use the auth_nonce cookie
    // to check that the JWT can be validated as being directly related to the
    // original request by this client. This mitigates against token replay attacks.
    var client_nonce_hash = "";
    if (req.variables.cookie_auth_nonce) {
        var c = require('crypto');
        var h = c.createHmac('sha256', req.variables.oidc_hmac_key).update(req.variables.cookie_auth_nonce);
        client_nonce_hash = h.digest('base64url');
    }
    if (req.variables.jwt_claim_nonce != client_nonce_hash) {
        req.error("OIDC ID Token validation error: nonce mismatch");
        valid_token = false;
    }

    if (valid_token) {
        res.return(204);
    } else {
        res.return(403);
    }
}
