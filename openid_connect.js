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
                    // Send the ID Token to auth_jwt location for validation
                    req.subrequest("/_id_token_validation", "token=" + tokenset.id_token + "&nonce=" + req.variables.cookie_auth_nonce,
                        function(reply) {
                            if (reply.status == 204) {
                                if (tokenset[req.variables.oidc_token_type]) {
                                    req.log("OIDC success, sending " + req.variables.oidc_token_type);
                                    auth_token = tokenset[req.variables.oidc_token_type]; // Export as NGINX variable
                                    res.return(302, req.variables.cookie_auth_redir);
                                } else {
                                    req.error("OIDC received id_token but not " + req.variables.oidc_token_type + " received");
                                    if (tokenset.error) {
                                        req.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                                    }
                                    res.return(500);
                                }
                            } else {
                                req.error("OIDC ID Token Validation failure " + reply.status + ", invalid or missing " + reply.body);
                                res.return(500);
                            }
                        }
                    );
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

function hashClientNonce(req) {
    if (req.variables.arg_nonce.length) {
        var c = require('crypto');
        var h = c.createHmac('sha256', req.variables.oidc_hmac_key).update(req.variables.arg_nonce);
        return(h.digest('base64'));
    } else {
        return "";
    }
}

function validateIdToken(req,res) {
    res.return(204);
}
