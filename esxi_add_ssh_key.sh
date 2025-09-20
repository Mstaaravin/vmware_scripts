#!/bin/bash

# -----------------------------------------------------------------------------
# scripts/esxi_add_ssh_key.sh
# Version: 1.2.2
# -----------------------------------------------------------------------------
# ESXi SSH Key Installation Script
#
# This script automates the process of adding SSH public keys to VMware ESXi 7.x hosts
# to enable passwordless SSH authentication. It provides a secure and reliable method
# for configuring SSH key-based access to ESXi management interfaces.
#
# FEATURES:
# - SSH ControlMaster for persistent connection reuse (improved efficiency)
# - Automatic SSH connection handling (password-based authentication for initial setup)
# - Comprehensive SSH key validation (format, type, and structure verification)
# - Automatic backup of existing authorized_keys before modifications
# - Duplicate key detection (prevents adding the same key multiple times)
# - Proper file permission handling (ESXi requires specific permissions for SSH files)
# - SSH service restart automation to apply changes
# - Complete verification of key installation success
# - Detailed logging with timestamps (both console and file output)
# - Optional SSH key authentication testing
#
# USAGE:
# 1. Configure the variables in the CONFIGURATION section below:
#    - ESXI_HOST: IP address, FQDN, or SSH alias of your ESXi host
#    - ESXI_PASSWORD: Leave empty to be prompted securely (recommended)
#    - PUBKEY_FILE: Path to your SSH public key file
#
# 2. Ensure prerequisites are met:
#    - sshpass installed for initial password authentication
#    - SSH access to ESXi host enabled
#    - Valid SSH public key file (RSA keys recommended for ESXi 7.x)
#
# 3. Execute the script: ./esxi_add_ssh_key.sh
#
# AUTHENTICATION PROCESS:
# - Initial Setup: Uses password authentication to install the SSH key
# - Post-Installation: Enables passwordless SSH key authentication
# - Verification: Tests both installation success and key functionality
#
# SAFETY FEATURES:
# - Automatic backup of existing authorized_keys file
# - Duplicate key detection and prevention
# - Comprehensive validation of SSH key format and structure
# - Service status verification after changes
# - Non-destructive operation (existing keys are preserved)
# - SSH ControlMaster for reliable connection reuse throughout the process
#
# OUTPUT:
# - Real-time progress logging to console
# - Complete execution log saved to timestamped file
# - Display of authorized_keys content for verification
# - SSH key authentication test results
#
# REQUIREMENTS:
# - VMware ESXi 7.x host with SSH enabled
# - Linux/Unix system with bash, ssh, and sshpass
# - Network connectivity to ESXi host
# - Valid SSH public key file (preferably RSA for ESXi compatibility)
# - Initial password access to ESXi host
# -----------------------------------------------------------------------------

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# =============================================================================
# CONFIGURATION VARIABLES - EDIT THESE VALUES
# =============================================================================

# ESXi connection details
ESXI_HOST="172.16.250.6"                    # ESXi host IP or FQDN
ESXI_USER="root"                              # ESXi username (usually root)
ESXI_PASSWORD=""       # ESXi password

# SSH public key file path
# on ESXi 7.x version, only rsa keys are allowed
PUBKEY_FILE="~/.ssh/keys/homelab/oralab.pub"               # Path to SSH public key file

# =============================================================================
# SCRIPT CONFIGURATION - USUALLY NO NEED TO MODIFY
# =============================================================================

# SSH connection options
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30"

# SSH ControlMaster configuration
CONTROL_SOCKET_DIR="/tmp"
CONTROL_SOCKET_PATH="$CONTROL_SOCKET_DIR/ssh-control-$$-$(date +%s)"

# Global variable to track authentication method
USE_SSH_KEY_AUTH=false

# =============================================================================
# FUNCTIONS
# =============================================================================

log() {
    # Log messages with timestamp to both stderr and optional log file
    # Parameters: $1 = message to log
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$message" >&2
    
    # Also log to file if LOG_FILE is set
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "$message" >> "$LOG_FILE"
    fi
}

error_exit() {
    # Log error message and exit with status 1
    # Parameters: $1 = error message
    log "ERROR: $1"
    cleanup_ssh_connection
    exit 1
}

cleanup_ssh_connection() {
    # Clean up SSH ControlMaster connection and socket file
    # Called on script exit or error
    if [[ -S "$CONTROL_SOCKET_PATH" ]]; then
        log "Cleaning up SSH ControlMaster connection..."
        ssh -S "$CONTROL_SOCKET_PATH" -O exit "$ESXI_USER@$ESXI_HOST" 2>/dev/null || true
        rm -f "$CONTROL_SOCKET_PATH" 2>/dev/null || true
        log "SSH connection cleanup completed"
    fi
}

expand_path() {
    # Expand tilde (~) in file paths to full home directory path
    # Parameters: $1 = path to expand
    # Returns: expanded path
    local path="$1"
    # Expand tilde to home directory
    if [[ "$path" =~ ^~/ ]]; then
        path="$HOME/${path:2}"  # Remove first 2 characters (~/) and prepend HOME
    elif [[ "$path" == "~" ]]; then
        path="$HOME"
    fi
    echo "$path"
}

check_configuration() {
    # Validate basic configuration variables and prompt for password if needed
    # Ensures ESXI_HOST is configured and handles password input securely
    log "Checking configuration..."

    # Check if configuration variables are properly set
    if [[ "$ESXI_HOST" == "192.168.1.100" ]]; then
        error_exit "Please update ESXI_HOST with your actual ESXi IP address"
    fi

    # Handle password input
    if [[ "$ESXI_PASSWORD" == "your_esxi_password_here" ]] || [[ -z "$ESXI_PASSWORD" ]]; then
        log "ESXi password not configured or empty"
        prompt_for_password
    fi

    log "Configuration check passed"
}

prompt_for_password() {
    # Securely prompt user for ESXi password (hidden input)
    # Updates global ESXI_PASSWORD variable
    log "Prompting for ESXi password..."

    # Check if we're in an interactive terminal
    if [[ ! -t 0 ]]; then
        error_exit "Password required but script is not running in interactive mode. Please set ESXI_PASSWORD variable."
    fi

    # Prompt for password securely
    echo -n "Enter ESXi password for $ESXI_USER@$ESXI_HOST: " >&2
    read -s ESXI_PASSWORD
    echo >&2

    # Validate password is not empty
    if [[ -z "$ESXI_PASSWORD" ]]; then
        error_exit "Password cannot be empty"
    fi

    log "Password entered successfully"
}

check_prerequisites() {
    # Validate required tools and SSH public key file exist and are readable
    # Expands file paths and performs basic file validation
    log "Checking prerequisites..."

    # Check if required tools are available
    command -v sshpass >/dev/null 2>&1 || error_exit "sshpass is required but not installed"
    command -v ssh >/dev/null 2>&1 || error_exit "ssh is required but not installed"

    # Check if control socket directory exists and is writable
    if [[ ! -d "$CONTROL_SOCKET_DIR" ]] || [[ ! -w "$CONTROL_SOCKET_DIR" ]]; then
        error_exit "Control socket directory $CONTROL_SOCKET_DIR is not writable"
    fi

    # Expand file paths
    PUBKEY_FILE=$(expand_path "$PUBKEY_FILE")

    # Check if required files exist
    [[ ! -f "$PUBKEY_FILE" ]] && error_exit "SSH public key file not found: $PUBKEY_FILE"

    # Check file permissions and readability
    [[ ! -r "$PUBKEY_FILE" ]] && error_exit "Cannot read SSH public key file: $PUBKEY_FILE"

    log "Prerequisites check passed"
    log "Using SSH public key: $PUBKEY_FILE"
}

establish_ssh_connection() {
    # Establish SSH ControlMaster connection to ESXi host using password authentication
    # This script specifically uses password auth for initial setup before key installation
    log "Establishing SSH ControlMaster connection to $ESXI_HOST..."

    # Set up trap to cleanup connection on script exit
    trap cleanup_ssh_connection EXIT

    # This script uses password authentication for initial setup (before SSH key is installed)
    # Test password-based connection and establish ControlMaster
    if sshpass -p "$ESXI_PASSWORD" ssh $SSH_OPTS -M -S "$CONTROL_SOCKET_PATH" -f -N "$ESXI_USER@$ESXI_HOST" 2>/dev/null; then
        log "SSH ControlMaster connection established successfully (using password)"
        USE_SSH_KEY_AUTH=false
        
        # Store password for reuse by subsequent connections
        export SSHPASS="$ESXI_PASSWORD"
    else
        error_exit "Cannot establish SSH ControlMaster connection to $ESXI_HOST using password authentication"
    fi
}

execute_remote_command() {
    # Execute command on remote ESXi host via SSH using established ControlMaster connection
    # Reuses the persistent connection established by establish_ssh_connection()
    # Parameters: $1 = command to execute, $2 = description for logging
    local command="$1"
    local description="$2"

    log "Executing: $description"

    # Verify ControlMaster connection is still active
    if ! ssh -S "$CONTROL_SOCKET_PATH" -O check "$ESXI_USER@$ESXI_HOST" >/dev/null 2>&1; then
        error_exit "SSH ControlMaster connection is not active"
    fi

    # Execute command using password authentication with ControlMaster
    local output
    if output=$(sshpass -e ssh -S "$CONTROL_SOCKET_PATH" "$ESXI_USER@$ESXI_HOST" "$command" 2>&1); then
        # Log each line of output to both console and file
        while IFS= read -r line; do
            echo "$line" >&2
            if [[ -n "${LOG_FILE:-}" ]]; then
                echo "$line" >> "$LOG_FILE"
            fi
        done <<< "$output"

        log "Successfully executed: $description"
        return 0
    else
        error_exit "Failed to execute: $description"
    fi
}

validate_ssh_key() {
    # Comprehensive validation of SSH public key file
    # Performs format validation and extracts key information for logging
    log "Validating SSH public key..."

    # Read the SSH public key content
    local ssh_public_key
    ssh_public_key=$(cat "$PUBKEY_FILE") || error_exit "Failed to read SSH public key file: $PUBKEY_FILE"

    # Validate SSH key format (basic check)
    if [[ ! "$ssh_public_key" =~ ^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-) ]]; then
        error_exit "Invalid SSH public key format in file: $PUBKEY_FILE"
    fi

    # Extract key information for logging
    local key_type comment
    key_type=$(echo "$ssh_public_key" | cut -d' ' -f1)
    comment=$(echo "$ssh_public_key" | cut -d' ' -f3- || echo "no comment")

    log "SSH public key is valid"
    log "  Key type: $key_type"
    log "  Comment: $comment"
    log "  File size: $(wc -c < "$PUBKEY_FILE") bytes"
}

add_ssh_key() {
    # Add SSH public key to ESXi authorized_keys file with proper handling
    # Creates backup, checks for duplicates, sets permissions, and reports results
    log "Adding SSH public key to authorized_keys..."

    # Read the SSH public key content
    local ssh_public_key
    ssh_public_key=$(cat "$PUBKEY_FILE") || error_exit "Failed to read SSH public key file: $PUBKEY_FILE"

    # Create the command to add SSH key
    local add_key_cmd="
        # Create directory if it doesn't exist
        mkdir -p /etc/ssh/keys-root

        # Backup current authorized_keys if it exists
        if [ -f /etc/ssh/keys-root/authorized_keys ]; then
            BACKUP_FILE=\"/etc/ssh/keys-root/authorized_keys.backup.\$(date +%Y%m%d_%H%M%S)\"
            cp /etc/ssh/keys-root/authorized_keys \"\$BACKUP_FILE\"
            echo \"Backup created: \$BACKUP_FILE\"
        fi

        # Add the new key if it's not already present
        if ! grep -q \"$(echo "$ssh_public_key" | cut -d' ' -f2)\" /etc/ssh/keys-root/authorized_keys 2>/dev/null; then
            echo \"$ssh_public_key\" >> /etc/ssh/keys-root/authorized_keys
            echo 'SSH key added successfully'
        else
            echo 'SSH key already exists'
        fi

        # Set proper permissions
        chmod 600 /etc/ssh/keys-root/authorized_keys
        chown root:root /etc/ssh/keys-root/authorized_keys

        # Display final file info
        echo \"Authorized keys file now contains \$(grep -c '^ssh-' /etc/ssh/keys-root/authorized_keys 2>/dev/null || echo 0) keys\"
    "

    execute_remote_command "$add_key_cmd" "Adding SSH public key"
}

restart_ssh_service() {
    # Restart ESXi SSH service to apply new key configuration
    # Uses standard ESXi service management commands with status verification
    log "Restarting SSH service..."

    # Restart SSH service
    execute_remote_command "/etc/init.d/SSH restart" "Restarting SSH service"

    # Wait a moment and check if service is running
    sleep 3
    execute_remote_command "/etc/init.d/SSH status" "Checking SSH service status"
}

verify_ssh_key() {
    # Comprehensive verification of SSH key installation
    # Checks key presence, file permissions, and displays authorized_keys content
    log "Verifying SSH key installation..."

    # Read SSH key for verification
    local ssh_key_fingerprint
    ssh_key_fingerprint=$(cat "$PUBKEY_FILE" | cut -d' ' -f2)

    # Verify SSH key was added
    local verify_cmd="
        echo '=== SSH Key Verification ==='
        if grep -q \"$ssh_key_fingerprint\" /etc/ssh/keys-root/authorized_keys 2>/dev/null; then
            echo 'SSH key verification: PASSED'
            echo \"Total keys in authorized_keys: \$(grep -c '^ssh-' /etc/ssh/keys-root/authorized_keys 2>/dev/null || echo 0)\"
            echo \"File permissions: \$(ls -l /etc/ssh/keys-root/authorized_keys | cut -d' ' -f1)\"
            echo ''
            echo '=== Current authorized_keys content ==='
            cat /etc/ssh/keys-root/authorized_keys
            echo ''
        else
            echo 'SSH key verification: FAILED'
            exit 1
        fi

        echo '=== SSH Service Status ==='
        /etc/init.d/SSH status
    "

    execute_remote_command "$verify_cmd" "Verifying SSH key installation"
}

test_key_authentication() {
    # Test SSH key authentication by attempting connection with private key
    # Optional verification step to confirm end-to-end functionality
    log "Testing SSH key authentication..."

    # Expand the private key path (assuming it's in the same directory as public key)
    local private_key_file
    private_key_file="${PUBKEY_FILE%.pub}"

    if [[ -f "$private_key_file" ]]; then
        log "Attempting to connect using private key: $private_key_file"

        if ssh $SSH_OPTS -i "$private_key_file" "$ESXI_USER@$ESXI_HOST" "echo 'SSH key authentication successful'" 2>/dev/null; then
            log "SSH key authentication test: PASSED"
        else
            log "SSH key authentication test: FAILED (this might be normal if the key has a passphrase or other restrictions)"
        fi
    else
        log "Private key file not found at expected location: $private_key_file"
        log "Skipping SSH key authentication test"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Main script execution flow with comprehensive logging and error handling
    # Sets up logging, validates inputs, installs SSH key, and verifies installation
    
    # Setup logging with timestamp
    local log_timestamp
    log_timestamp=$(date '+%y%m%d_%H%M%S')
    LOG_FILE="esxi_add_ssh_key-${log_timestamp}.log"
    
    log "Starting ESXi SSH key installation script"
    log "Target host: $ESXI_HOST"
    log "Log file: $(pwd)/$LOG_FILE"
    
    # Expand and display the SSH key path early for verification
    PUBKEY_FILE=$(expand_path "$PUBKEY_FILE")
    log "SSH key file: $PUBKEY_FILE"

    # Step 1: Check basic configuration
    check_configuration

    # Step 2: Check prerequisites (tools and files)
    check_prerequisites

    # Step 3: Validate SSH key format and structure
    validate_ssh_key

    # Step 4: Establish SSH ControlMaster connection with password
    establish_ssh_connection

    # Step 5: Add SSH public key to authorized_keys
    add_ssh_key

    # Step 6: Restart SSH service to apply changes
    restart_ssh_service

    # Step 7: Verify SSH key installation success
    verify_ssh_key

    # Step 8: Test key authentication (optional verification)
    test_key_authentication

    log "SSH key installation completed successfully!"
    log "You should now be able to connect using SSH key authentication:"
    log "  ssh -i ${PUBKEY_FILE%.pub} $ESXI_USER@$ESXI_HOST"
    log "Complete log saved to: $(pwd)/$LOG_FILE"
    
    # Cleanup is handled by the trap
}

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

# Check if script is being sourced or executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly - run main function
    main "$@"
fi
