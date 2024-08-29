#!/bin/bash

set -e

test -n "$TEST_URL" || { echo "TEST_URL not set"; exit 1; }
test -n "$TEST_USER" || { echo "TEST_USER not set"; exit 1; }
test -n "$TEST_PWD" || { echo "TEST_PWD not set"; exit 1; }
test -n "$CLIENT_ID" || { echo "CLIENT_ID not set, leaving it empty"; }
test -n "$REDIRECT_URI" || { echo "REDIRECT_URI not set, leaving it empty"; }
test -n "$SCOPE" || { echo "SCOPE not set, leaving it empty"; }

# Step 1: Start ZAP in Docker
docker run --rm -u zap -p 8081:8080 -p 8090:8090 -p 8091:8091 -d --name zap-container zaproxy/zap-stable zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
trap "docker stop zap-container" EXIT SIGINT SIGTERM

# Step 2: Manually Obtain Authorization Code
# You'll need to manually obtain the authorization code by directing the user to the authorization URL.
# Replace the placeholders with your actual values.

AUTH_URL="${TEST_URL}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=${SCOPE}&code_challenge=abc"
echo "AUTH_URL: ${AUTH_URL}"
curl -v --user "${TEST_USER}:${TEST_PWD}" "$AUTH_URL"

# The user will copy the authorization code from the browser's redirected URL.
read -p "Enter the authorization code: " AUTH_CODE

# Step 3: Exchange Authorization Code for Access Token
ACCESS_TOKEN=$(curl -X POST "https://auth.example.com/oauth2/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code" \
     -d "code=$AUTH_CODE" \
     -d "redirect_uri=https://yourapp.com/callback" \
     -d "client_id=your_client_id" \
     -d "client_secret=your_client_secret" | jq -r '.access_token')

# Step 4: Configure ZAP Context
docker exec -it zap-container zap-cli context-create "OAuth2 API Context"
docker exec -it zap-container zap-cli context-import OAuth2 "OAuth2 API Context"
docker exec -it zap-container zap-cli auth-method set-bearer-token "OAuth2 API Context" --token "$ACCESS_TOKEN"
docker exec -it zap-container zap-cli context-include "OAuth2 API Context" "https://api.example.com/.*"

# Step 5: Spider and Active Scan
docker exec -it zap-container zap-cli spider --context "OAuth2 API Context" "https://api.example.com"
docker exec -it zap-container zap-cli active-scan --context "OAuth2 API Context" "https://api.example.com"

# Step 6: Retrieve Report
docker exec -it zap-container zap-cli report -o zap_report.html -f html

# Step 7: Cleanup
docker stop zap-container

