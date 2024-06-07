#!/usr/bin/env bash
# configure.sh (c) NGINX, Inc. [18-May-2020] Liam Crilly <liam.crilly@nginx.com>

COMMAND=${0##*/}
CONFDIR=${0%/*}
if [ $# -lt 1 ]; then
	echo "USAGE: $COMMAND [options] <OpenID Connect configuration URL>"
	echo ""
	echo "Configures NGINX Plus OpenID Connect reference implementation by using the IdP's Discovery interface"
	echo "Multiple IdPs may be configured by specifying the --host option"
	echo ""
	echo " URL typically ends with '/openid-configuration'"
	echo " Options:"
	echo " -h | --host <server_name>           # Configure for specific host (server FQDN)"
	echo " -k | --auth_jwt_key <file|request>  # Use auth_jwt_key_file (default) or auth_jwt_key_request"
	echo " -i | --client_id <id>               # Client ID as obtained from OpenID Connect Provider"
	echo " -s | --client_secret <secret>       # Client secret as obtained from OpenID Connect Provider"
	echo " -p | --pkce_enable                  # Enable PKCE for this client"
	echo " -x | --insecure                     # Do not verify IdP's SSL certificate"
	echo ""
	exit 1
fi

# Process command line options
#
DO_JWKS_URI=0
CLIENT_ID=""
CLIENT_SECRET=""
PKCE=0
HOSTNAME="default"
SED_BAK=".ORIG"
while [ $# -gt 1 ]; do
	case "$1" in
		"-k" | "--auth_jwt_key" | "--auth-jwt-key")
			if [ "$2" == "request" ]; then
				DO_JWKS_URI=1
			elif [ "$2" != "file" ]; then
				echo "$COMMAND: ERROR: Valid arguments to $1 are 'file' or 'request'"
				exit 1
			fi
			shift; shift
			;;
		"-i" | "--client_id" | "--client-id")
			CLIENT_ID=$2
			shift; shift
			;;
		"-s" | "--client_secret" | "--client-secret")
			CLIENT_SECRET=$2
			shift; shift
			;;
		"-p" | "--pkce_enable" | "--pkce-enable" | "--enable_pkce" | "--enable-pkce")
			PKCE=1
			shift
			;;
		"-h" | "--host" )
			HOSTNAME=$2
			shift; shift
			;;
		"-x" | "--insecure" )
			CURL_OPT="-k "
			WGET_OPT="--no-check-certificate "
			shift
			;;
		*)
			echo "$COMMAND: ERROR: Invalid command line option ($1) - quitting"
			exit 1
			;;
	esac
done
IDP_URL=$1

# Multiple IdPs should use auth_jwt_key_request
#
if [[ $DO_JWKS_URI -eq 0 && "$HOSTNAME" != "default" ]]; then
	echo "$COMMAND: ERROR: Using multiple IdPs requires --auth_jwt_key request"
	exit 1
fi

# Check for dependencies
#
hash jq 2> /dev/null
if [ $? -ne 0 ]; then
	echo "$COMMAND: ERROR: 'jq' must be installed"
	jq
	exit 1
fi

for http_cli in "wget ${WGET_OPT}-q -O -" "curl ${CURL_OPT}-sS"; do
	hash ${http_cli%% *} 2> /dev/null # Remove chars beyond space
	if [ $? -eq 0 ]; then
		GET_URL=$http_cli
		break #for
	fi
done
if [ "$GET_URL" == "" ]; then
	echo "$COMMAND: ERROR: 'curl' or 'wget' must be installed to download configuration data"
	exit 1
fi

# Download the OpenID Connect Discovery document
$GET_URL $IDP_URL > /tmp/${COMMAND}_$$_json

# Test for exit error
if [ $? -ne 0 ]; then
	echo "$COMMAND: ERROR: Unable to connect to $IDP_URL"
	cat /tmp/${COMMAND}_$$_json
	rm /tmp/${COMMAND}_$$_json
	exit 1
fi

# Test for valid JSON object
jq -r .authorization_endpoint < /tmp/${COMMAND}_$$_json 2>&1 | grep -c ^http > /dev/null
if [ $? -ne 0 ]; then
	echo "$COMMAND: ERROR: $IDP_URL returned invalid OpenID Connect Discovery document"
	cat /tmp/${COMMAND}_$$_json
	rm /tmp/${COMMAND}_$$_json
	exit 1
fi

# Build an intermediate configuration file
# File format is: <NGINX variable name><space><IdP value>
#
jq -r '. | "$oidc_authz_endpoint \(.authorization_endpoint)\n$oidc_token_endpoint \(.token_endpoint)\n$oidc_end_session_endpoint \(.end_session_endpoint // "")\n$oidc_jwks_uri \(.jwks_uri)"' < /tmp/${COMMAND}_$$_json > /tmp/${COMMAND}_$$_conf

# Create a random value for HMAC key, adding to the intermediate configuration file
echo "\$oidc_hmac_key `openssl rand -base64 18`" >> /tmp/${COMMAND}_$$_conf

# Add client ID and secret to the intermediate configuration file (if provided)
if [ "$CLIENT_ID" != "" ]; then
	CLIENT_ID_VAR=\$oidc_client
	echo "\$oidc_client $CLIENT_ID" >> /tmp/${COMMAND}_$$_conf
fi
if [ "$CLIENT_SECRET" != "" ]; then
	CLIENT_SECRET_VAR=\$oidc_client_secret
	echo "\$oidc_client_secret $CLIENT_SECRET" >> /tmp/${COMMAND}_$$_conf
fi

# Add PKCE configuration
PKCE_ENABLE_VAR=\$oidc_pkce_enable
echo "\$oidc_pkce_enable $PKCE" >> /tmp/${COMMAND}_$$_conf

# Fetch or configure the JWK file depending on configuration input
# Also apply appropriate auth_jwt_key_ configuration directive.
#
JWKS_URI=`jq -r .jwks_uri < /tmp/${COMMAND}_$$_json`
if [ $DO_JWKS_URI -eq 0 ]; then
	echo "$COMMAND: NOTICE: Downloading $CONFDIR/idp_jwk.json"
	$GET_URL $JWKS_URI > $CONFDIR/idp_jwk.json
	if [ $? -ne 0 ] || [ ! -s $CONFDIR/idp_jwk.json ]; then
		echo "$COMMAND: ERROR: Failed to download from $JWKS_URI"
		cat $CONFDIR/idp_jwk.json
		exit 1
	fi
	echo "\$oidc_jwt_keyfile conf.d/idp_jwk.json" >> /tmp/${COMMAND}_$$_conf
	echo "s/#\(auth_jwt_key_file\)/\1/" > /tmp/${COMMAND}_$$_sed # Uncomment
	echo "s/ \(auth_jwt_key_request\)/ #\1/" >> /tmp/${COMMAND}_$$_sed # Comment-out
else
	echo "\$oidc_jwt_keyfile $JWKS_URI" >> /tmp/${COMMAND}_$$_conf
	echo "s/ \(auth_jwt_key_file\)/ #\1/" > /tmp/${COMMAND}_$$_sed # Comment-out
	echo "s/#\(auth_jwt_key_request\)/\1/" >> /tmp/${COMMAND}_$$_sed # Uncomment
fi

# Perform the substitutions on frontend.conf for auth_jwt_key_
#
echo -n "$COMMAND: NOTICE: Configuring $CONFDIR/frontend.conf ..."
sed -i$SED_BAK -f /tmp/${COMMAND}_$$_sed $CONFDIR/frontend.conf
if [ $? -ne 0 ]; then
	echo " FAILED"
        echo "$COMMAND: ERROR: $CONFDIR/frontend.conf failed, check intermediate files `ls -1 /tmp/${COMMAND}_$$_* | tr '\n' ' '`"
	exit 1
fi
diff $CONFDIR/frontend.conf $CONFDIR/frontend.conf$SED_BAK > /dev/null
if [ $? -eq 0 ]; then
	echo " no change"
else
	echo " ok"
fi

# Loop through each configuration variable
echo "$COMMAND: NOTICE: Configuring $CONFDIR/openid_connect_configuration.conf"
for OIDC_VAR in \$oidc_authz_endpoint \$oidc_token_endpoint \$oidc_end_session_endpoint \$oidc_jwt_keyfile \$oidc_hmac_key $CLIENT_ID_VAR $CLIENT_SECRET_VAR $PKCE_ENABLE_VAR; do
	# Pull the configuration value from the intermediate file
	VALUE=`grep "^$OIDC_VAR " /tmp/${COMMAND}_$$_conf | cut -f2 -d' '`
	echo -n "$COMMAND: NOTICE:  - $OIDC_VAR ..."

	# If the value is empty, assign a default value
	if [ -z "$VALUE" ]; then
		VALUE="\"\""
	fi

	# Find where this variable is configured
	LINE=`grep -nA10 $OIDC_VAR $CONFDIR/openid_connect_configuration.conf | grep -vE '^[0-9]+-?[[:space:]]*($|#)' | grep $HOSTNAME | head -1 | cut -f1 -d-`
	if [ "$LINE" == "" ]; then
		# Add new value
		LINE=`grep -n $OIDC_VAR $CONFDIR/openid_connect_configuration.conf | head -1 | cut -f1 -d:`
		sed -i$SED_BAK "${LINE}a\\
\    $HOSTNAME $VALUE;\\
" $CONFDIR/openid_connect_configuration.conf
	else
		# Replace existing value
		sed -i$SED_BAK "${LINE}c\\
\    $HOSTNAME $VALUE;\\
" $CONFDIR/openid_connect_configuration.conf
	fi

	if [ $? -ne 0 ]; then
		echo " FAILED"
		echo "$COMMAND: ERROR: $OIDC_VAR failed, check intermediate files `ls -1 /tmp/${COMMAND}_$$_* | tr '\n' ' '`"
		exit 1
	fi

	diff $CONFDIR/openid_connect_configuration.conf $CONFDIR/openid_connect_configuration.conf$SED_BAK > /dev/null
	if [ $? -eq 0 ]; then
		echo " no change"
	else
		echo " ok"
	fi
done

echo "$COMMAND: NOTICE: Success - test configuration with 'nginx -t'"
rm /tmp/${COMMAND}_$$_*
