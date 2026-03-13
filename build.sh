#!/usr/bin/env bash
# Build and deploy luducat bridge plugin to Windows KVM for testing.
# Usage: ./build.sh [--deploy] [--clean]
#
# Requires:
#   - Windows builder VM running (vm_start)
#   - .NET 8.0 SDK installed on VM
#   - Playnite installed on VM

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BUILD_TOOLS_DIR="$HOME/bin/build-tools"

# Source VM helpers
source "$BUILD_TOOLS_DIR/kvm/common.sh"
source "$BUILD_TOOLS_DIR/windows/config.sh"

VM_BUILD_DIR="/c/BUILD/luducat-bridge"
VM_PLAYNITE_EXT_DIR="/c/Users/pulaski/AppData/Local/Playnite/Extensions/LuducatBridge"

DEPLOY=false
CLEAN=false

for arg in "$@"; do
    case "$arg" in
        --deploy) DEPLOY=true ;;
        --clean) CLEAN=true ;;
    esac
done

echo "=== luducat Bridge Build ==="

# Check VM is running
if ! vm_is_running; then
    echo "ERROR: Windows builder VM is not running. Run 'vm_start' first."
    exit 1
fi

# Sync source to VM
echo "Syncing source to VM..."
vm_ssh "mkdir -p '$VM_BUILD_DIR'"
vm_scp_to "$PROJECT_DIR/src/" "$VM_BUILD_DIR/src/"
vm_scp_to "$PROJECT_DIR/LuducatBridge.sln" "$VM_BUILD_DIR/"
vm_scp_to "$PROJECT_DIR/extension.yaml" "$VM_BUILD_DIR/"

if [ -f "$PROJECT_DIR/icon.png" ]; then
    vm_scp_to "$PROJECT_DIR/icon.png" "$VM_BUILD_DIR/"
fi

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning..."
    vm_ssh "cd '$VM_BUILD_DIR' && dotnet clean LuducatBridge.sln -c Release" || true
fi

# Build
echo "Building..."
vm_ssh "cd '$VM_BUILD_DIR' && dotnet build LuducatBridge.sln -c Release"

BUILD_EXIT=$?
if [ $BUILD_EXIT -ne 0 ]; then
    echo "ERROR: Build failed with exit code $BUILD_EXIT"
    exit $BUILD_EXIT
fi

echo "Build succeeded."

# Deploy to Playnite extensions directory
if [ "$DEPLOY" = true ]; then
    echo "Deploying to Playnite extensions..."
    vm_ssh "mkdir -p '$VM_PLAYNITE_EXT_DIR'"

    # Copy build output
    vm_ssh "cp -r '$VM_BUILD_DIR/src/bin/Release/net8.0-windows/'* '$VM_PLAYNITE_EXT_DIR/'"

    # Copy extension manifest and icon
    vm_ssh "cp '$VM_BUILD_DIR/extension.yaml' '$VM_PLAYNITE_EXT_DIR/'"
    vm_ssh "[ -f '$VM_BUILD_DIR/icon.png' ] && cp '$VM_BUILD_DIR/icon.png' '$VM_PLAYNITE_EXT_DIR/'" || true

    echo "Deployed to $VM_PLAYNITE_EXT_DIR"
    echo "Restart Playnite to load the plugin."
fi

echo "=== Done ==="
