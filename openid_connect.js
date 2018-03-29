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
            req.log("OIDC error receiving authorization code from IdP: " + req.variables.arg_error_description);
        } else {
            req.log("OIDC expected authorization code from IdP but received: " + req.variables.uri);
        }
        res.status = 502;
        res.sendHeader();
        res.finish();
        return;
    }

    // Pass the authorization code to the /_token location so that it can be
    // proxied to the IdP in exchange for a JWT
    var isValid = 0;
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
                                    res.status = 302;
                                    auth_token = tokenset[req.variables.oidc_token_type]; // Export as NGINX variable
                                    res.headers.Location = req.variables.cookie_auth_redir;
                                } else {
                                    req.log("OIDC authorization code sent but no token received. " + tokenset.error + " " + tokenset.error_description);
                                    res.status = 500;
                                }
                            } else {
                                req.log("OIDC ID Token Validation failure " + reply.status + ", invalid or missing " + reply.body);
                                res.status = 500;
                            }
                            res.sendHeader();
                            res.finish();
                        }
                    );
                } catch (e) { 
                    req.log("OIDC authorization code sent but response is not JSON. " + reply.body);
                    //req.log("Writing response to /tmp/oidc_token_response");
                    //var fs = require('fs');
                    //fs.writeFileSync('/tmp/oidc_token_response', reply.body)
                    res.status = 502;
                    res.sendHeader();
                    res.finish();
                }
            } else if (reply.status == 504) {
                req.log("OIDC timeout connecting to IdP when sending authorization code");
                res.status = 504;
                res.sendHeader();
                res.finish();
            } else {
                try {
                    var errorset = JSON.parse(reply.body);
                    if (errorset.error) {
                        req.log("OIDC error from IdP when sending authorization code: " + errorset.error + ", " + errorset.error_description);
                    } else {
                        req.log("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.body);
                    }
                } catch (e) {
                    req.log("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.body);
                }
                res.status = 503;
                res.sendHeader();
                res.finish();
            }
        }
    );
}

function get_auth_token(req,res) {
    return auth_token;
}

function hashRequestId(req) {
    var c = require('crypto');
    var h = c.createHash('sha256').update(req.variables.request_id);
    return(h.digest('hex'));
}

function hashClientNonce(req) {
    if (req.variables.arg_nonce.length) {
        var c = require('crypto');
        var h = c.createHash('sha256').update(req.variables.arg_nonce);
        return(h.digest('hex'));
    } else {
        return "";
    }
}

function noContent(req,res) {
    res.status = 204;
    res.sendHeader();
    res.finish();
}
