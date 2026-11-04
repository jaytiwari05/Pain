#!/usr/bin/env bash
# setup_pain.sh - build and deploy the Pain C2 agent + listener into an Adaptix installation.
# Works for both first-time setup and subsequent rebuilds (all steps are idempotent).
#
# Usage:
#   ./setup_pain.sh --ax /path/to/AdaptixC2
#
# What it does:
#   1. Checks required tools are installed
#   2. Registers Pain's Go modules in go.work (first-time only)
#   3. Patches profile.yaml to list Pain's extenders (first-time only)
#   4. Generates TLS certs if they don't exist yet (first-time only)
#   5. Builds both plugins and the server binary
#   6. Deploys everything to dist/extenders/

set -e

PAIN_ROOT="$(cd "$(dirname "$0")" && pwd)"


# Helpers

ok()   { echo "  [OK]  $*"; }
info() { echo "  [--]  $*"; }
step() { echo ""; echo "[$1] $2"; }
die()  { echo ""; echo "  [ERR] $*" >&2; exit 1; }


# Parse arguments

AX_ROOT=""

usage() {
    echo ""
    echo "Usage: $0 --ax <adaptix-root>"
    echo ""
    echo "  --ax   Path to the AdaptixC2 root directory"
    echo "         (the one that contains dist/ and AdaptixServer/)"
    echo ""
    echo "Example: $0 --ax /home/pain/Documents/AdaptixC2"
    echo ""
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ax)  AX_ROOT="$(realpath "$2")"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
done

[[ -z "$AX_ROOT" ]]    && { echo "Error: --ax is required"; usage; }
[[ ! -d "$AX_ROOT" ]]  && die "Adaptix root not found: $AX_ROOT"


# Derived paths

AX_SERVER="$AX_ROOT/AdaptixServer"
AX_DIST="$AX_ROOT/dist"
GOWORK="$AX_SERVER/go.work"
PROFILE_DIST="$AX_DIST/profile.yaml"
PROFILE_SRC="$AX_SERVER/profile.yaml"
EXTENDERS_DIR="$AX_DIST/extenders"

AGENT_SRC="$PAIN_ROOT/agent_pain/src_server"
LISTENER_SRC="$PAIN_ROOT/listener_pain_http/src_server"

AGENT_EXTENDER="$EXTENDERS_DIR/agent_pain"
LISTENER_EXTENDER="$EXTENDERS_DIR/listener_pain_http"

# Go module paths relative to go.work location (AdaptixServer/) - computed dynamically
# so the same script works regardless of where the repos are checked out
AGENT_MOD_REL="$(realpath --relative-to="$AX_SERVER" "$PAIN_ROOT/agent_pain/src_server")"
LISTENER_MOD_REL="$(realpath --relative-to="$AX_SERVER" "$PAIN_ROOT/listener_pain_http")"

export GOWORK

echo ""
echo "Pain setup"
echo "  Pain root    : $PAIN_ROOT"
echo "  Adaptix root : $AX_ROOT"
echo "  GOWORK       : $GOWORK"


# Step 1 - Check required tools

step "1/8" "Checking required tools..."

check_tool() {
    if command -v "$1" &>/dev/null; then
        ok "$1 found ($(command -v "$1"))"
    else
        die "$1 not found - please install it first.
       $2"
    fi
}

check_tool "go"                      "Install Go: https://go.dev/doc/install"
check_tool "nasm"                    "On Kali/Ubuntu: sudo apt install nasm"
check_tool "x86_64-w64-mingw32-g++"  "On Kali/Ubuntu: sudo apt install mingw-w64"
check_tool "openssl"                 "On Kali/Ubuntu: sudo apt install openssl"


# Step 2 - Register Pain modules in go.work (first-time only)

step "2/8" "Checking go.work..."

[[ ! -f "$GOWORK" ]] && die "go.work not found at $GOWORK - is the Adaptix root correct?"

register_gomod() {
    local rel="$1"
    local label="$2"
    # exact-line match to avoid substring false-positives (e.g. foo vs foo/src_server)
    if grep -qxF "	$rel" "$GOWORK" 2>/dev/null; then
        ok "$label already in go.work"
    else
        info "Adding $label to go.work..."
        sed -i "/^)$/i\\\\t$rel" "$GOWORK"
        ok "$label added to go.work"
    fi
}

prune_gomod() {
    local rel="$1"
    local label="$2"
    if grep -qxF "	$rel" "$GOWORK" 2>/dev/null; then
        info "Removing stale $label entry from go.work..."
        sed -i "\|^[[:space:]]*${rel}[[:space:]]*\$|d" "$GOWORK"
        ok "$label stale entry removed"
    fi
}

# Remove stale entries left by older runs of this script
prune_gomod "../../Pain/agent_pain/src_server"  "old agent_pain/src_server"
prune_gomod "../../Pain/listener_pain_http"      "old listener_pain_http"
prune_gomod "../../Pain/listener_pain_http/src_server" "listener_pain_http/src_server (no go.mod)"

register_gomod "$AGENT_MOD_REL"    "agent_pain/src_server"
register_gomod "$LISTENER_MOD_REL" "listener_pain_http"


# Step 3 - Patch profile.yaml to list Pain extenders (first-time only)

step "3/8" "Checking profile.yaml..."

patch_profile() {
    local profile="$1"
    [[ ! -f "$profile" ]] && { info "profile.yaml not found at $profile - skipping"; return; }

    local changed=0

    for entry in \
        "extenders/agent_pain/config.yaml" \
        "extenders/listener_pain_http/config.yaml"
    do
        if grep -qF "$entry" "$profile" 2>/dev/null; then
            ok "$entry already in $(basename "$(dirname "$profile")")/profile.yaml"
        else
            info "Adding $entry to $(basename "$(dirname "$profile")")/profile.yaml..."
            # Insert after the 'extenders:' line
            sed -i "/extenders:/a\\    - \"$entry\"" "$profile"
            ok "$entry added"
            changed=1
        fi
    done
}

patch_profile "$PROFILE_DIST"
patch_profile "$PROFILE_SRC"


# Step 4 - Generate TLS certs if missing (first-time only)

step "4/8" "Checking TLS certificates..."

CERT="$AX_DIST/server.rsa.crt"
KEY="$AX_DIST/server.rsa.key"

if [[ -f "$CERT" && -f "$KEY" ]]; then
    ok "Certs already exist - skipping generation"
else
    info "Generating self-signed RSA-2048 cert (valid 10 years)..."
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$KEY" \
        -out    "$CERT" \
        -days   3650 \
        -subj   "/CN=adaptix-c2/O=Pain/C=US" \
        -quiet
    ok "server.rsa.crt and server.rsa.key generated in $AX_DIST"
fi


# Step 5 - Build agent plugin

step "5/8" "Building agent plugin..."
cd "$AGENT_SRC"
go build -buildmode=plugin -o pain.so .
ok "pain.so built"


# Step 6 - Build listener plugin

step "6/8" "Building listener plugin..."
cd "$LISTENER_SRC"
go build -buildmode=plugin -o listener_pain_http.so .
ok "listener_pain_http.so built"


# Step 7 - Rebuild adaptixserver (must match plugin build)

step "7/8" "Rebuilding adaptixserver..."
cd "$AX_SERVER"
go build -o "$AX_DIST/adaptixserver" .
ok "adaptixserver rebuilt"


# Step 8 - Deploy to extenders/

step "8/8" "Deploying to extenders/..."

mkdir -p "$AGENT_EXTENDER" "$LISTENER_EXTENDER"

cp "$AGENT_SRC/pain.so"                          "$AGENT_EXTENDER/pain.so"
cp "$LISTENER_SRC/listener_pain_http.so"         "$LISTENER_EXTENDER/listener_pain_http.so"
cp "$PAIN_ROOT/agent_pain/ax_config.axs"         "$AGENT_EXTENDER/ax_config.axs"
cp "$PAIN_ROOT/listener_pain_http/ax_config.axs" "$LISTENER_EXTENDER/ax_config.axs"

# Write agent config.yaml
cat > "$AGENT_EXTENDER/config.yaml" <<'EOF'
extender_type: "agent"
extender_file: "pain.so"
ax_file: "ax_config.axs"

agent_name: "pain"
agent_watermark: "deadbeef"
listeners:
  - "PainHTTP"
multi_listeners: false
EOF

# Write listener config.yaml
cat > "$LISTENER_EXTENDER/config.yaml" <<'EOF'
extender_type: "listener"
extender_file: "listener_pain_http.so"
ax_file: "ax_config.axs"

listener_name: "PainHTTP"
listener_type: "external"
protocol: "http"
EOF

# Symlink the agent source tree so the plugin resolves ModuleDir/src_agent at runtime.
# A symlink (not a copy) means edits to agent_pain/ take effect on the next UI build
# without re-running this script.
ln -sfn "$PAIN_ROOT/agent_pain" "$AGENT_EXTENDER/src_agent"
ok "src_agent symlink -> $PAIN_ROOT/agent_pain"

ok "Files deployed"


# Done

echo ""
echo "  Pain is ready."
echo ""
echo "  Agent extender   : $AGENT_EXTENDER"
echo "  Listener extender: $LISTENER_EXTENDER"
echo "  Server binary    : $AX_DIST/adaptixserver"
echo ""
echo "  Start the server:"
echo "    cd $AX_DIST && ./adaptixserver -c profile.yaml"
echo ""
