#!/bin/bash

# -----------------------------------------------------------------------------
# scripts/esxi_replace_ssl_certs.sh
# Version: 1.0.4
# -----------------------------------------------------------------------------

# Script to replace SSL certificates on ESXi 7 host
# This script performs the following tasks:
# 1. Replace SSL certificate (rui.crt)
# 2. Replace SSL private key (rui.key)
# 3. Restart hostd service

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# =============================================================================
# CONFIGURATION VARIABLES - EDIT THESE VALUES
# =============================================================================

# ESXi connection details
ESXI_HOST="172.16.250.6"                    # ESXi host IP or FQDN
ESXI_USER="root"                              # ESXi username (usually root)
ESXI_PASSWORD=""       # ESXi password

# SSL certificate file paths
SSL_CERT_FILE="~/Projects/git.certgen/domains/lan/certs/vmware.lan-fullchain.crt" # Path to SSL certificate file
SSL_KEY_FILE="~/Projects/git.certgen/domains/lan/certs/vmware.lan.key"      # Path to SSL private key file

# =============================================================================
# SCRIPT CONFIGURATION - USUALLY NO NEED TO MODIFY
# =============================================================================

# SSH connection options
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30"

# ESXi SSL file paths
ESXI_CERT_PATH="/etc/vmware/ssl/rui.crt"
ESXI_KEY_PATH="/etc/vmware/ssl/rui.key"

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
    
    # Check if it might be an SSH alias before prompting for password
    local might_be_alias=false
    if [[ ! "$ESXI_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ ! "$ESXI_HOST" =~ \. ]]; then
        if [[ -f "$HOME/.ssh/config" ]] && grep -q "^Host $ESXI_HOST$" "$HOME/.ssh/config" 2>/dev/null; then
            might_be_alias=true
            log "Detected SSH alias '$ESXI_HOST' - will try SSH key authentication first"
        fi
    fi
    
    # Handle password input only if not using SSH alias or if password is explicitly set
    if [[ "$ESXI_PASSWORD" == "your_esxi_password_here" ]] || [[ -z "$ESXI_PASSWORD" ]]; then
        if [[ "$might_be_alias" == false ]]; then
            log "ESXi password not configured or empty"
            prompt_for_password
        else
            log "ESXi password not configured - will attempt SSH key authentication for alias"
        fi
    fi
    
    if [[ "$SSL_CERT_FILE" == "/path/to/your/certificate.crt" ]]; then
        error_exit "Please update SSL_CERT_FILE with the path to your SSL certificate"
    fi
    
    if [[ "$SSL_KEY_FILE" == "/path/to/your/private.key" ]]; then
        error_exit "Please update SSL_KEY_FILE with the path to your SSL private key"
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
    SSL_CERT_FILE=$(expand_path "$SSL_CERT_FILE")
    SSL_KEY_FILE=$(expand_path "$SSL_KEY_FILE")
    
    # Check if required files exist
    [[ ! -f "$SSL_CERT_FILE" ]] && error_exit "SSL certificate file not found: $SSL_CERT_FILE"
    [[ ! -f "$SSL_KEY_FILE" ]] && error_exit "SSL private key file not found: $SSL_KEY_FILE"
    
    # Check file permissions and readability
    [[ ! -r "$SSL_CERT_FILE" ]] && error_exit "Cannot read SSL certificate file: $SSL_CERT_FILE"
    [[ ! -r "$SSL_KEY_FILE" ]] && error_exit "Cannot read SSL private key file: $SSL_KEY_FILE"
    
    log "Prerequisites check passed"
    log "Using SSL certificate: $SSL_CERT_FILE"
    log "Using SSL private key: $SSL_KEY_FILE"
}


test_ssh_connection() {
    log "Testing SSH connection to $ESXI_HOST..."
    
    # Check if ESXI_HOST might be an SSH alias
    local is_alias=false
    if [[ ! "$ESXI_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ ! "$ESXI_HOST" =~ \. ]]; then
        # Looks like it could be an alias (not an IP and no dots for FQDN)
        if [[ -f "$HOME/.ssh/config" ]] && grep -q "^Host $ESXI_HOST$" "$HOME/.ssh/config" 2>/dev/null; then
            is_alias=true
            log "Detected SSH alias '$ESXI_HOST' in ~/.ssh/config"
            
            # Try SSH key authentication first for aliases
            if ssh $SSH_OPTS "$ESXI_USER@$ESXI_HOST" "echo 'SSH connection successful'" >/dev/null 2>&1; then
                log "SSH connection to $ESXI_HOST successful (using SSH key)"
                return 0
            else
                log "SSH key authentication failed, need password"
            fi
        fi
    fi
    
    # If we reach here, we need password authentication
    if [[ -z "$ESXI_PASSWORD" ]]; then
        log "ESXi password required for connection"
        prompt_for_password
    fi
    
    # Test password-based connection
    if sshpass -p "$ESXI_PASSWORD" ssh $SSH_OPTS "$ESXI_USER@$ESXI_HOST" "echo 'SSH connection successful'" >/dev/null 2>&1; then
        log "SSH connection to $ESXI_HOST successful"
    else
        if [[ "$is_alias" == true ]]; then
            error_exit "Cannot establish SSH connection to alias '$ESXI_HOST'. Check if the alias is correctly configured in ~/.ssh/config and the target host is reachable."
        else
            error_exit "Cannot establish SSH connection to $ESXI_HOST"
        fi
    fi
}



execute_remote_command() {
    local command="$1"
    local description="$2"

    log "Executing: $description"

    # Execute command and capture output
    local output
    
    # Use password authentication (since we know it works from test_ssh_connection)
    if output=$(sshpass -p "$ESXI_PASSWORD" ssh $SSH_OPTS "$ESXI_USER@$ESXI_HOST" "$command" 2>&1); then
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


validate_ssl_files() {
    log "Validating SSL certificate and private key..."
    
    # Read certificate and key content
    local ssl_certificate ssl_private_key
    ssl_certificate=$(cat "$SSL_CERT_FILE") || error_exit "Failed to read SSL certificate file: $SSL_CERT_FILE"
    ssl_private_key=$(cat "$SSL_KEY_FILE") || error_exit "Failed to read SSL private key file: $SSL_KEY_FILE"
    
    # Basic validation of certificate format
    if [[ ! "$ssl_certificate" =~ -----BEGIN.*CERTIFICATE----- ]]; then
        error_exit "Invalid SSL certificate format in file: $SSL_CERT_FILE"
    fi
    
    if [[ ! "$ssl_certificate" =~ -----END.*CERTIFICATE----- ]]; then
        error_exit "Invalid SSL certificate format in file: $SSL_CERT_FILE"
    fi
    
    # Basic validation of private key format
    if [[ ! "$ssl_private_key" =~ -----BEGIN.*PRIVATE.KEY----- ]] && [[ ! "$ssl_private_key" =~ -----BEGIN.RSA.PRIVATE.KEY----- ]]; then
        error_exit "Invalid SSL private key format in file: $SSL_KEY_FILE"
    fi
    
    if [[ ! "$ssl_private_key" =~ -----END.*PRIVATE.KEY----- ]] && [[ ! "$ssl_private_key" =~ -----END.RSA.PRIVATE.KEY----- ]]; then
        error_exit "Invalid SSL private key format in file: $SSL_KEY_FILE"
    fi
    
    log "SSL certificate format is valid"
    log "  Certificate file size: $(wc -c < "$SSL_CERT_FILE") bytes"
    log "SSL private key format is valid"
    log "  Private key file size: $(wc -c < "$SSL_KEY_FILE") bytes"
    
    # Additional validation with openssl if available
    if command -v openssl >/dev/null 2>&1; then
        log "Performing additional validation with openssl..."
        
        # Validate certificate
        if openssl x509 -in "$SSL_CERT_FILE" -noout -text >/dev/null 2>&1; then
            log "SSL certificate is valid (verified with openssl)"
            
            # Show certificate details
            local cert_subject cert_dates
            cert_subject=$(openssl x509 -in "$SSL_CERT_FILE" -noout -subject 2>/dev/null | cut -d'=' -f2-)
            cert_dates=$(openssl x509 -in "$SSL_CERT_FILE" -noout -dates 2>/dev/null)
            
            log "  Certificate Subject: $cert_subject"
            log "  $cert_dates"
            
            # Check if certificate is expired
            local end_date
            end_date=$(openssl x509 -in "$SSL_CERT_FILE" -noout -enddate 2>/dev/null | cut -d'=' -f2)
            if [[ -n "$end_date" ]]; then
                local end_epoch current_epoch
                end_epoch=$(date -d "$end_date" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$end_date" +%s 2>/dev/null || echo "0")
                current_epoch=$(date +%s)
                
                if [[ "$end_epoch" -gt 0 ]] && [[ "$current_epoch" -gt "$end_epoch" ]]; then
                    log "  WARNING: Certificate has expired!"
                elif [[ "$end_epoch" -gt 0 ]]; then
                    local days_left=$(( (end_epoch - current_epoch) / 86400 ))
                    if [[ "$days_left" -lt 30 ]]; then
                        log "  WARNING: Certificate expires in $days_left days"
                    else
                        log "  Certificate is valid for $days_left more days"
                    fi
                fi
            fi
        else
            error_exit "SSL certificate validation failed with openssl"
        fi
        
        # Validate private key
        if openssl rsa -in "$SSL_KEY_FILE" -check -noout >/dev/null 2>&1 || openssl pkey -in "$SSL_KEY_FILE" -check -noout >/dev/null 2>&1; then
            log "SSL private key is valid (verified with openssl)"
        else
            error_exit "SSL private key validation failed with openssl"
        fi
        
        # Validate certificate and key match
        local cert_modulus key_modulus
        cert_modulus=$(openssl x509 -noout -modulus -in "$SSL_CERT_FILE" 2>/dev/null | openssl md5 2>/dev/null || echo "")
        key_modulus=$(openssl rsa -noout -modulus -in "$SSL_KEY_FILE" 2>/dev/null | openssl md5 2>/dev/null || \
                      openssl pkey -noout -text -in "$SSL_KEY_FILE" 2>/dev/null | openssl md5 2>/dev/null || echo "")
        
        if [[ -n "$cert_modulus" ]] && [[ -n "$key_modulus" ]] && [[ "$cert_modulus" == "$key_modulus" ]]; then
            log "Certificate and private key match"
        else
            error_exit "Certificate and private key do not match!"
        fi
    else
        log "openssl not available - skipping advanced validation"
    fi
}

backup_existing_certificates() {
    log "Creating backup of existing SSL certificates..."
    
    local backup_cmd="
        BACKUP_SUFFIX=\$(date +%Y%m%d_%H%M%S)
        
        # Check if current certificates exist
        if [ -f $ESXI_CERT_PATH ]; then
            cp $ESXI_CERT_PATH ${ESXI_CERT_PATH}.backup.\$BACKUP_SUFFIX
            echo 'Certificate backup created: ${ESXI_CERT_PATH}.backup.'\$BACKUP_SUFFIX
        else
            echo 'No existing certificate found at $ESXI_CERT_PATH'
        fi
        
        if [ -f $ESXI_KEY_PATH ]; then
            cp $ESXI_KEY_PATH ${ESXI_KEY_PATH}.backup.\$BACKUP_SUFFIX
            echo 'Private key backup created: ${ESXI_KEY_PATH}.backup.'\$BACKUP_SUFFIX
        else
            echo 'No existing private key found at $ESXI_KEY_PATH'
        fi
        
        echo 'Backup completed with suffix: '\$BACKUP_SUFFIX
    "
    
    execute_remote_command "$backup_cmd" "Creating backup of existing certificates"
}

replace_ssl_certificates() {
    log "Replacing SSL certificates on ESXi host..."
    
    # Read certificate and key content
    local ssl_certificate ssl_private_key
    ssl_certificate=$(cat "$SSL_CERT_FILE") || error_exit "Failed to read SSL certificate file: $SSL_CERT_FILE"
    ssl_private_key=$(cat "$SSL_KEY_FILE") || error_exit "Failed to read SSL private key file: $SSL_KEY_FILE"
    
    # Step 1: Change permissions of existing key file to allow writing
    log "Step 1: Preparing to replace SSL files..."
    local prep_cmd="
        echo 'Preparing SSL file replacement...'
        if [ -f $ESXI_KEY_PATH ]; then
            chmod 600 $ESXI_KEY_PATH
            echo 'Changed permissions on existing private key'
        fi
        echo 'Ready to replace SSL files'
    "
    execute_remote_command "$prep_cmd" "Preparing SSL file replacement"
    
    # Step 2: Replace SSL certificate
    log "Step 2: Replacing SSL certificate file..."
    local cert_cmd="
        echo 'Replacing SSL certificate...'
        cat > $ESXI_CERT_PATH << 'EOF_CERT'
$ssl_certificate
EOF_CERT
        echo 'SSL certificate file created successfully'
    "
    execute_remote_command "$cert_cmd" "Replacing SSL certificate file"
    
    # Step 3: Replace SSL private key
    log "Step 3: Replacing SSL private key file..."
    local key_cmd="
        echo 'Replacing SSL private key...'
        cat > $ESXI_KEY_PATH << 'EOF_KEY'
$ssl_private_key
EOF_KEY
        echo 'SSL private key file created successfully'
    "
    execute_remote_command "$key_cmd" "Replacing SSL private key file"
    
    # Step 4: Set final permissions
    log "Step 4: Setting final file permissions..."
    local perm_cmd="
        chmod 400 $ESXI_KEY_PATH
        chmod 644 $ESXI_CERT_PATH
        chown root:root $ESXI_CERT_PATH $ESXI_KEY_PATH
        echo 'Final permissions set successfully'
    "
    execute_remote_command "$perm_cmd" "Setting final SSL file permissions"
    
    # Step 5: Verify files
    log "Step 5: Verifying SSL files..."
    local verify_cmd="
        if [ -f $ESXI_CERT_PATH ] && [ -f $ESXI_KEY_PATH ]; then
            echo 'SSL certificates replaced successfully'
            echo \"Certificate size: \$(wc -c < $ESXI_CERT_PATH) bytes\"
            echo \"Private key size: \$(wc -c < $ESXI_KEY_PATH) bytes\"
            echo \"Certificate permissions: \$(ls -l $ESXI_CERT_PATH | cut -d' ' -f1)\"
            echo \"Private key permissions: \$(ls -l $ESXI_KEY_PATH | cut -d' ' -f1)\"
        else
            echo 'ERROR: Failed to create SSL certificate files'
            exit 1
        fi
    "
    execute_remote_command "$verify_cmd" "Verifying SSL certificate installation"
}


restart_hostd_service() {
    log "Restarting hostd service..."
    
    # Stop hostd service first
    execute_remote_command "/etc/init.d/hostd stop" "Stopping hostd service"
    
    # Wait a moment
    sleep 3
    
    # Start hostd service
    execute_remote_command "/etc/init.d/hostd start" "Starting hostd service"
    
    # Wait for service to fully start
    sleep 5
    
    # Check service status
    execute_remote_command "/etc/init.d/hostd status" "Checking hostd service status"
}

verify_ssl_installation() {
    log "Verifying SSL certificate installation..."
    
    local verify_cmd="
        echo '=== SSL Certificate Verification ==='
        if [ -f $ESXI_CERT_PATH ] && [ -f $ESXI_KEY_PATH ]; then
            echo 'SSL certificate files exist: PASSED'
            echo \"Certificate permissions: \$(ls -l $ESXI_CERT_PATH | cut -d' ' -f1)\"
            echo \"Private key permissions: \$(ls -l $ESXI_KEY_PATH | cut -d' ' -f1)\"
            echo \"Certificate size: \$(wc -c < $ESXI_CERT_PATH) bytes\"
            echo \"Private key size: \$(wc -c < $ESXI_KEY_PATH) bytes\"
        else
            echo 'SSL certificate files: FAILED'
            exit 1
        fi
        
        echo '=== Certificate Content Check ==='
        if openssl x509 -in $ESXI_CERT_PATH -noout -subject -issuer -dates 2>/dev/null; then
            echo 'Certificate parsing: PASSED'
        else
            echo 'Certificate parsing: FAILED'
        fi
        
        echo '=== hostd Service Status ==='
        /etc/init.d/hostd status
    "
    
    execute_remote_command "$verify_cmd" "Verifying SSL certificate installation"
}

test_https_connection() {
    log "Testing HTTPS connection to ESXi host..."
    
    if command -v curl >/dev/null 2>&1; then
        log "Testing HTTPS connection with curl..."
        if curl -k -s --connect-timeout 10 "https://$ESXI_HOST/" >/dev/null; then
            log "HTTPS connection test: PASSED"
        else
            log "HTTPS connection test: FAILED (this might be normal during service restart)"
        fi
    elif command -v wget >/dev/null 2>&1; then
        log "Testing HTTPS connection with wget..."
        if wget --no-check-certificate --timeout=10 -q -O /dev/null "https://$ESXI_HOST/" 2>/dev/null; then
            log "HTTPS connection test: PASSED"
        else
            log "HTTPS connection test: FAILED (this might be normal during service restart)"
        fi
    else
        log "Neither curl nor wget available - skipping HTTPS connection test"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Setup logging
    local log_timestamp
    log_timestamp=$(date '+%y%m%d_%H%M%S')
    LOG_FILE="esxi_replace_ssl_certs-${log_timestamp}.log"
    
    log "Starting ESXi SSL certificate replacement script"
    log "Target host: $ESXI_HOST"
    log "Log file: $(pwd)/$LOG_FILE"
    
    # Expand and display the SSL file paths early
    SSL_CERT_FILE=$(expand_path "$SSL_CERT_FILE")
    SSL_KEY_FILE=$(expand_path "$SSL_KEY_FILE")
    log "SSL certificate file: $SSL_CERT_FILE"
    log "SSL private key file: $SSL_KEY_FILE"
    
    # Step 1: Check prerequisites first (file validation)
    check_prerequisites
    
    # Step 2: Validate SSL files
    validate_ssl_files
    
    # Step 3: Test SSH connection BEFORE asking for password
    test_ssh_connection
    
    # Step 4: Backup existing certificates
    backup_existing_certificates
    
    # Step 5: Replace SSL certificates
    replace_ssl_certificates
    
    # Step 6: Restart hostd service
    restart_hostd_service
    
    # Step 7: Verify SSL installation
    verify_ssl_installation
    
    # Step 8: Test HTTPS connection
    test_https_connection
    
    log "SSL certificate replacement completed successfully!"
    log "ESXi web interface should now use the new SSL certificates"
    log "You can access the host at: https://$ESXI_HOST/"
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
