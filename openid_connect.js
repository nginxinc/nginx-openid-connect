/*
 * nginScript functions for providing OpenID Connect authorization
 * code flow with NGINX Plus.
 *
 * Copyright (C) 2018 Nginx, Inc.
 */

var auth_token = "";

function oidc_codeExchange(req, res) {
    // First check that we received an authorization code from the IdP
    if (req.variables.arg_code.length == 0) {
        if (req.variables.arg_error) {
            req.error("OIDC error receiving authorization code from IdP: " + req.variables.arg_error_description);
        } else {
            req.error("OIDC expected authorization code from IdP but received: " + req.variables.uri);
        }
        res.return(502);
    }

    // Pass the authorization code to the /_token location so that it can be
    // proxied to the IdP in exchange for a JWT
    req.subrequest("/_token", {"args":"code=" + req.variables.arg_code,"method":"POST"},
        function(reply) {
            if (reply.status == 200) {
                try {
                    var tokenset = JSON.parse(reply.body);
                    if (tokenset[req.variables.oidc_token_type]) {
                        // Send the ID Token to auth_jwt location for validation
                        req.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
                            function(reply) {
                                if (reply.status == 204) {
                                    req.log("OIDC success, sending " + req.variables.oidc_token_type);
                                    auth_token = tokenset[req.variables.oidc_token_type]; // Export as NGINX variable
                                    res.return(302, req.variables.cookie_auth_redir);
                                } else {
                                    res.return(500);
                                }
                            }
                        );
                    } else {
                        req.error("OIDC received id_token but not " + req.variables.oidc_token_type + " received");
                        if (tokenset.error) {
                            req.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                        }
                        res.return(500);
                    }
                } catch (e) {
                    req.error("OIDC authorization code sent but token response is not JSON. " + reply.body);
                    res.return(502);
                }
            } else if (reply.status == 504) {
                req.error("OIDC timeout connecting to IdP when sending authorization code");
                res.return(504);
            } else {
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
            }
        }
    );
}

function get_auth_token(req,res) {
    return auth_token;
}

function hashRequestId(req) {
    var c = require('crypto');
    var h = c.createHmac('sha256', req.variables.oidc_hmac_key).update(req.variables.request_id);
    return(h.digest('base64'));
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
    }

    // Check iat is a number
    var iat = Math.floor(Number(req.variables.jwt_claim_iat));
    if (String(iat) != req.variables.jwt_claim_iat || iat < 1) {
        req.error("OIDC ID Token validation error: iat claim is not a valid number");
        res.return(403);
    }

    // TODO: Check iss is substring of IdP root URL

    // Audience matching
    if (req.variables.jwt_claim_aud != req.variables.oidc_client) {
        req.error("OIDC ID Token validation error: aud claim does not match $oidc_client");
        res.return(403);
    }

    // If we receive a nonce in the ID Token then we will use the auth_nonce cookie
    // to check that the JWT can be validated as being directly related to the
    // original request by this client. This mitigates against token replay attacks.
    var client_nonce_hash = "";
    if (req.variables.cookie_auth_nonce) {
        var c = require('crypto');
        var h = c.createHmac('sha256', req.variables.oidc_hmac_key).update(req.variables.cookie_auth_nonce);
        client_nonce_hash = h.digest('base64');
    }
    if (req.variables.jwt_claim_nonce != client_nonce_hash) {
        req.error("OIDC ID Token validation error: nonce mismatch");
        res.return(403);
    }

    res.return(204); // ID Token validation successful
}
