#!/bin/bash
# Ghost Firewall 认证网关 8443 完整渗透测试 —— 第 2 轮（续跑）
# 第 1 轮 workspace=nftgw-233e-20261029 因 token 限额在 recon 阶段失败（AGENT_EXECUTION_FAILED）
# 本轮沿用同一 workspace 名触发 auto-resume，并加 --keep-container 便于事后诊断
set -e
export NVM_DIR="$HOME/.nvm"
. "$NVM_DIR/nvm.sh"
export PATH="$NVM_DIR/versions/node/v24.21.0/bin:$PATH"

MODELS=/home/kirito/shannon-reports/models-mm-20261029.json
export SHANNON_AI_MODEL="minimax:MiniMax-M3"
export SHANNON_AI_API_KEY=$(python3 -c "import json;print(json.load(open(\"$MODELS\"))[\"providers\"][\"minimax\"][\"apiKey\"])")
export SHANNON_AI_BASE_URL="https://api.minimax.cn/v1"
unset OPENAI_API_KEY

TARGET_URL="https://192.168.100.233:8443"
REPO_PATH="/home/kirito/shannon-repos/nftgw-prod-20261029"
WORKSPACE="nftgw-233e-20261029"
OUTPUT_DIR="/home/kirito/shannon-reports/nftgw-233e-20261029"
CONFIG_FILE="/home/kirito/shannon-reports/nftgw-auth-20261029.yaml"

mkdir -p "$OUTPUT_DIR"
echo "=== Shannon 认证网关 8443 渗透测试 第2轮(续跑) ==="
echo "Target:    $TARGET_URL"
echo "Repo:      $REPO_PATH"
echo "Model:     $SHANNON_AI_MODEL"
echo "Workspace: $WORKSPACE (auto-resume)"
echo "Start:     $(date "+%F %T")"
echo

cd /home/kirito/shannon-h43-scan
shannon start \
  -u "$TARGET_URL" \
  -r "$REPO_PATH" \
  -c "$CONFIG_FILE" \
  --models-config "$MODELS" \
  -w "$WORKSPACE" \
  -o "$OUTPUT_DIR" \
  --keep-container \
  -f 2>&1 | tee /home/kirito/shannon-nftgw-20261029-run2.log

echo
echo "=== 结束 $(date "+%F %T") workspace=$WORKSPACE ==="
