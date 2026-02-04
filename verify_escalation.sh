#!/bin/bash
set -e

# ==============================================================================
# PetPulse Alert Escalation Verification
# ==============================================================================
# Loops 5 times to trigger:
# 1-2: Mild Intervention
# 3: Moderate Intervention
# 4: Notification + Last Autonomous
# 5: High Severity + Quick Actions
# ==============================================================================

SERVER_URL="https://preview.petpulse.clestiq.com"
COOKIE_JAR="cookies_escalation.txt"
EMAIL="vasubhut25102002@gmail.com"
PASSWORD="password123"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=== PetPulse Alert Escalation Test ===${NC}"

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: 'jq' is required.${NC}"
    exit 1
fi

if [ ! -f "assets/pacing.mp4" ]; then
    echo -e "${RED}Error: 'assets/pacing.mp4' not found.${NC}"
    exit 1
fi

# 1. Register & Login
echo -e "\n${BLUE}--- Step 1: Login & Setup ---${NC}"
echo "Attempting login for $EMAIL..."
LOGIN_RES=$(curl -s -c $COOKIE_JAR -X POST $SERVER_URL/login -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")

if echo "$LOGIN_RES" | grep -q "Login successful" || echo "$LOGIN_RES" | grep -q "OK"; then
    echo -e "${GREEN}Login successful!${NC}"
else
    echo "Login failed. Attempting registration..."
    REGISTER_RES=$(curl -s -X POST $SERVER_URL/register -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"name\":\"Escalation User\"}")
    if echo "$REGISTER_RES" | grep -q "id"; then
        echo -e "${GREEN}Registration successful!${NC}"
        # Login again to get cookies
        curl -s -c $COOKIE_JAR -X POST $SERVER_URL/login -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" > /dev/null
    else
        echo -e "${RED}Registration failed: $REGISTER_RES${NC}"
        exit 1
    fi
fi

# Fetch User ID from /users endpoint (protected)
echo "Fetching User ID..."
USER_INFO=$(curl -s -b $COOKIE_JAR -X GET $SERVER_URL/users)
USER_ID=$(echo $USER_INFO | jq -r '.id')
echo -e "${GREEN}Logged in as User ID: $USER_ID${NC}"

# 2. Create Pet
echo -e "\n${BLUE}--- Step 2: Create Pet ---${NC}"
PET_RES=$(curl -s -b $COOKIE_JAR -X POST $SERVER_URL/pets -H "Content-Type: application/json" -d '{"name":"EscalationPup","age":2,"species":"Dog","breed":"Lab","bio":"Testing limits"}')
PET_ID=$(echo $PET_RES | jq -r '.id')
echo -e "${GREEN}Created Pet ID: $PET_ID${NC}"

# 3. Create Emergency Contact (Needed for Quick Actions)
echo -e "\n${BLUE}--- Step 3: Create Emergency Contact ---${NC}"
CONTACT_RES=$(curl -s -b $COOKIE_JAR -X POST $SERVER_URL/emergency-contacts -H "Content-Type: application/json" -d '{"name":"Neighbors","phone":"+15550000001","contact_type":"Neighbor","email":"neighbor@email.com"}')
echo "DEBUG: Contact Response: $CONTACT_RES"
CONTACT_ID=$(echo $CONTACT_RES | jq -r '.id')
echo -e "${GREEN}Created Contact ID: $CONTACT_ID${NC}"

# 4. Trigger 5 Alerts
echo -e "\n${BLUE}--- Step 4: Triggering 5 Alerts ---${NC}"

for ((i=1; i<=5; i++)); do
    echo -e "\n${BLUE}[Alert $i/5] Uploading 'pacing.mp4'...${NC}"
    
    UPLOAD_RES=$(curl -s -b $COOKIE_JAR -X POST -F "video=@assets/pacing.mp4" $SERVER_URL/pets/$PET_ID/upload_video)
    VIDEO_ID=$(echo $UPLOAD_RES | jq -r '.video_id')
    echo "Uploaded Video ID: $VIDEO_ID"
    
    echo "Waiting 30s for processing..."
    sleep 30

    # Show logs specifically for this alert processing from K8s
    echo "--- Agent Logs for Alert $i ---"
    AGENT_POD=$(kubectl get pods -l app=petpulse-agent -o jsonpath="{.items[0].metadata.name}")
    kubectl logs "$AGENT_POD" --tail 20 2>&1 | grep -E "Deciding intervention|Action:|Escalation|ComfortLoop" || true
    echo "-------------------------------"
    
    # Optional: Check standard output logs to confirm progression
    if [ $i -eq 4 ]; then
        echo -e "${GREEN}(Expect: Notification + Last Autonomous Action)${NC}"
    elif [ $i -eq 5 ]; then
        echo -e "${GREEN}(Expect: High Severity + Quick Actions)${NC}"
    fi
done

# Check Alerts via API
echo "Checking recent alerts via API..."
ALERTS_JSON=$(curl -s -b $COOKIE_JAR -X GET "$SERVER_URL/pets/$PET_ID/alerts")
echo "$ALERTS_JSON" | jq -r '.[]? | "ID: \(.id), Severity: \(.severity_level), Action: \(.intervention_action)"' | head -n 5

# Check Quick Actions via API
echo -e "\nChecking for Generated Quick Actions via API..."
# First get all alerts to find their UUIDs
ALL_ALERTS=$(curl -s -b $COOKIE_JAR -X GET "$SERVER_URL/alerts")
echo "$ALL_ALERTS" | jq -r '.[].id' | while read -r ALERT_UUID; do
    ACTIONS_RES=$(curl -s -b $COOKIE_JAR -X GET "$SERVER_URL/alerts/$ALERT_UUID/quick-actions")
    if echo "$ACTIONS_RES" | jq -e '. | length > 0' > /dev/null 2>&1; then
        echo "Alert $ALERT_UUID actions:"
        echo "$ACTIONS_RES" | jq .
    fi
done

echo -e "\n${GREEN}Test Complete. Review DB output above.${NC}"
rm -f $COOKIE_JAR
