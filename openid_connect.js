/*
 * OpenID Connect functions
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
    req.subrequest("/_token", {"args":"code=" + req.variables.arg_code,"method":"POST"},
        function(reply) {
            if (reply.status == 200) {
                try {
                    var tokenset = JSON.parse(reply.body);
                    req.log("OIDC received tokenset, accessing " + req.variables.oidc_token_type);
                    if (tokenset[req.variables.oidc_token_type]) {
                        res.status = 302;
                        auth_token = tokenset[req.variables.oidc_token_type]; // Export as NGINX variable
                        res.headers.Location = req.variables.cookie_auth_redir;
                    } else {
                        res.log("OIDC authorization code sent but no token received. " + tokenset.error + " " + tokenset.error_description);
                        res.status = 500;
                    }
                } catch (e) { 
                    req.log("OIDC authorization code sent but response is not JSON. " + reply.body);
                    res.status = 502;
                }
            } else if (reply.status == 504) {
                req.log("OIDC timeout connecting to IdP when sending authorization code");
                res.status = 504;
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
            }
            res.sendHeader();
            res.finish();
        }
    );
}

function get_auth_token(req,res) {
    return auth_token;
}

function hash_RequestId(req) {
    var c = require('crypto');
    var h = c.createHash('sha256').update(req.variables.request_id);
    return(h.digest('hex'));
}

function hash_NonceCookie(req) {
    var c = require('crypto');
    var h = c.createHash('sha256').update(req.variables.cookie_auth_nonce);
    return(h.digest('hex'));
}
