#!/bin/bash
set -e

GATEWAY_URL="http://localhost:3110/test-billing-event"
BILLING_URL="http://localhost:8080/usage?api_key=test-api-key"

# 1. Trigger test billing event
echo "[1/3] Triggering test billing event via gateway..."
RESPONSE=$(curl -s -X POST "$GATEWAY_URL")
echo "Gateway response: $RESPONSE"

if [[ "$RESPONSE" != *'"success":true'* ]]; then
  echo "Test event not accepted by gateway!"
  exit 1
fi

# 2. Wait for event to propagate
sleep 2

# 3. Query billing service for usage
echo "[2/3] Querying billing service for test-api-key usage..."
USAGE=$(curl -s "$BILLING_URL")
echo "Billing service usage response: $USAGE"

# 4. Check if the event is present
if [[ "$USAGE" == *'"request_count":'* && "$USAGE" == *'"total_cost":'* ]]; then
  echo "[3/3] End-to-end billing test PASSED."
  exit 0
else
  echo "[3/3] End-to-end billing test FAILED."
  exit 2
fi 