#!/bin/bash

# -----------------------------------------------------------------------------
# scripts/esxi_add_ssh_key.sh
# Version: 1.1.3
# -----------------------------------------------------------------------------

# Script to add SSH public key to ESXi 7 host
# This script performs the following tasks:
# 1. Add SSH public key to authorized_keys
# 2. Restart SSH service

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

# =============================================================================
# FUNCTIONS
# =============================================================================

log() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$message" >&2
    
    # Also log to file if LOG_FILE is set
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "$message" >> "$LOG_FILE"
    fi
}


error_exit() {
    log "ERROR: $1"
    exit 1
}

expand_path() {
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
    log "Checking prerequisites..."

    # Check if required tools are available
    command -v sshpass >/dev/null 2>&1 || error_exit "sshpass is required but not installed"
    command -v ssh >/dev/null 2>&1 || error_exit "ssh is required but not installed"

    # Expand file paths
    PUBKEY_FILE=$(expand_path "$PUBKEY_FILE")

    # Check if required files exist
    [[ ! -f "$PUBKEY_FILE" ]] && error_exit "SSH public key file not found: $PUBKEY_FILE"

    # Check file permissions and readability
    [[ ! -r "$PUBKEY_FILE" ]] && error_exit "Cannot read SSH public key file: $PUBKEY_FILE"

    log "Prerequisites check passed"
    log "Using SSH public key: $PUBKEY_FILE"
}

test_ssh_connection() {
    log "Testing SSH connection to $ESXI_HOST..."

    if sshpass -p "$ESXI_PASSWORD" ssh $SSH_OPTS "$ESXI_USER@$ESXI_HOST" "echo 'SSH connection successful'" >/dev/null 2>&1; then
        log "SSH connection to $ESXI_HOST successful"
    else
        error_exit "Cannot establish SSH connection to $ESXI_HOST"
    fi
}


execute_remote_command() {
    local command="$1"
    local description="$2"

    log "Executing: $description"

    # Execute command and capture output
    local output
    if output=$(sshpass -p "$ESXI_PASSWORD" ssh $SSH_OPTS "$ESXI_USER@$ESXI_HOST" "$command" 2>&1); then
        # Log each line of output
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
    log "Validating SSH public key..."

    # Read the SSH public key content
    local ssh_public_key
    ssh_public_key=$(cat "$PUBKEY_FILE") || error_exit "Failed to read SSH public key file: $PUBKEY_FILE"

    # Validate SSH key format (basic check)
    if [[ ! "$ssh_public_key" =~ ^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-) ]]; then
        error_exit "Invalid SSH public key format in file: $PUBKEY_FILE"
    fi

    local key_type comment
    key_type=$(echo "$ssh_public_key" | cut -d' ' -f1)
    comment=$(echo "$ssh_public_key" | cut -d' ' -f3- || echo "no comment")

    log "SSH public key is valid"
    log "  Key type: $key_type"
    log "  Comment: $comment"
    log "  File size: $(wc -c < "$PUBKEY_FILE") bytes"
}



add_ssh_key() {
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
    log "Restarting SSH service..."

    # Restart SSH service
    execute_remote_command "/etc/init.d/SSH restart" "Restarting SSH service"

    # Wait a moment and check if service is running
    sleep 3
    execute_remote_command "/etc/init.d/SSH status" "Checking SSH service status"
}



verify_ssh_key() {
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
    # Setup logging
    local log_timestamp
    log_timestamp=$(date '+%y%m%d_%H%M%S')
    LOG_FILE="esxi_add_ssh_key-${log_timestamp}.log"
    
    log "Starting ESXi SSH key installation script"
    log "Target host: $ESXI_HOST"
    log "Log file: $(pwd)/$LOG_FILE"
    
    # Expand and display the SSH key path early
    PUBKEY_FILE=$(expand_path "$PUBKEY_FILE")
    log "SSH key file: $PUBKEY_FILE"

    # Step 1: Check configuration
    check_configuration

    # Step 2: Check prerequisites
    check_prerequisites

    # Step 3: Validate SSH key
    validate_ssh_key

    # Step 4: Test SSH connection
    test_ssh_connection

    # Step 5: Add SSH public key
    add_ssh_key

    # Step 6: Restart SSH service
    restart_ssh_service

    # Step 7: Verify SSH key installation
    verify_ssh_key

    # Step 8: Test key authentication (optional)
    test_key_authentication

    log "SSH key installation completed successfully!"
    log "You should now be able to connect using SSH key authentication:"
    log "  ssh -i ${PUBKEY_FILE%.pub} $ESXI_USER@$ESXI_HOST"
    log "Complete log saved to: $(pwd)/$LOG_FILE"
}


# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly
    main "$@"
fi
