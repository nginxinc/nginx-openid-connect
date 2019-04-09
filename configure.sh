#!/usr/bin/env bash
# configure.sh (c) NGINX, Inc. [23-Nov-2018] Liam Crilly <liam.crilly@nginx.com>

COMMAND=${0##*/}
CONFDIR=${0%/*}
if [ $# -lt 1 ]; then
	echo "USAGE: $COMMAND [options] <OpenID Connect configuration URL>"
	echo ""
	echo "Configures NGINX Plus OpenID Connect reference implementation by using the IdP's Discovery interface"
	echo ""
	echo " URL typically ends with '/openid-configuration'"
	echo " Options:"
	echo " -k | --auth_jwt_key <file|request>  # Use auth_jwt_key_file (default) or auth_jwt_key_request (R17+)"
	echo " -i | --client_id <id>               # Client ID as obtained from OpenID Connect Provider"
	echo " -s | --client_secret <secret>       # Client secret as obtained from OpenID Connect Provider"
	echo " -x | --insecure                     # Do not verify IdP's SSL certificate"
	echo " -d | --dry_run                      # Produce configuration to stdout without modifying frontend.conf"
	echo ""
	exit 1
fi

# Process command line options
#
DO_JWKS_URI=0
CLIENT_ID=""
CLIENT_SECRET=""
SED_OPT="-i.ORIG "
while [ $# -gt 1 ]; do
	case "$1" in
		"-k" | "--auth_jwt_key")
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
		"-x" | "--insecure" )
			CURL_OPT="-k "
			WGET_OPT="--no-check-certificate "
			shift
			;;
		"-d" | "--dry_run" | "--dry-run")
			SED_OPT=""
			shift
			;;
		*)
			echo "$COMMAND: ERROR: Invalid command line option ($1) - quitting"
			exit 1
			;;
	esac
done
IDP_URL=$1

# Check for dependencies
#
hash jq 2> /dev/null
if [ $? -ne 0 ]; then
	echo "$COMMAND: ERROR: 'jq' must be installed"
	jq
	exit 1
fi

for http_cli in  "wget ${WGET_OPT}-q -O -" "curl ${CURL_OPT}-sS"; do
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

# Build an intermediate configuration file (will be converted to sed(1) command file.
# File format is: <NGINX variable name><space><IdP value>
#
jq -r '. | "$oidc_authz_endpoint \(.authorization_endpoint)\n$oidc_token_endpoint \(.token_endpoint)\n$oidc_jwks_uri \(.jwks_uri)"' < /tmp/${COMMAND}_$$_json > /tmp/${COMMAND}_$$_conf

# Create a random value for HMAC key, adding to the base mapping file
echo "\$oidc_hmac_key `openssl rand -base64 18`" >> /tmp/${COMMAND}_$$_conf

# Add client ID and secret to the base mapping file (if provided)
if [ "$CLIENT_ID" != "" ]; then
	echo "\$oidc_client $CLIENT_ID" >> /tmp/${COMMAND}_$$_conf
fi
if [ "$CLIENT_SECRET" != "" ]; then
	echo "\$oidc_client_secret $CLIENT_SECRET" >> /tmp/${COMMAND}_$$_conf
fi

# Fetch or configure the JWK file depending on configuration input
# Also apply appropriate auth_jwt_key_ configuration directive.
# NB: auth_jwt_key_request requires NGINX Plus R17 or later
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

# Build the sed(1) command file (requires a lot of escaping)
#
sed -e "s/\//\\\\\//g" /tmp/${COMMAND}_$$_conf | awk '{print "s/\\("$1"\\) \\(.*\\);/\\1 \""$2"\";/"}' >> /tmp/${COMMAND}_$$_sed

# Perform the substitutions on frontend.conf
#
echo "$COMMAND: NOTICE: Configuring $CONFDIR/frontend.conf"
sed ${SED_OPT}-f /tmp/${COMMAND}_$$_sed $CONFDIR/frontend.conf

if [ $? -eq 0 ]; then
	echo "$COMMAND: NOTICE: Success - test configuration with 'nginx -t'"
	rm /tmp/${COMMAND}_$$_*
else
	echo "$COMMAND: ERROR: Configuration failed, check intermediate files `ls -1 /tmp/${COMMAND}_$$_* | tr '\n' ' '`"
fi
