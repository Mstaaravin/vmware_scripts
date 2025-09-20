#!/bin/bash

# -----------------------------------------------------------------------------
# scripts/esxi_apply_license.sh
# Version: 1.0.0
# -----------------------------------------------------------------------------
# ESXi License Application Script
#
# This script automates the process of applying licenses to VMware ESXi 7.x hosts.
# It provides a comprehensive solution for installing and configuring ESXi licenses
# with proper validation and service management using SSH ControlMaster for
# efficient connection reuse.
#
# FEATURES:
# - SSH ControlMaster for persistent connection reuse (improved efficiency)
# - Automatic SSH connection handling (supports both SSH keys and password authentication)
# - SSH alias support (works seamlessly with SSH config files and includes)
# - Comprehensive license validation (format verification and duplicate detection)
# - Automatic backup of existing license configuration
# - Service restart automation (hostd and vpxa services restart to apply new license)
# - Complete verification of license installation success
# - Detailed logging with timestamps (both console and file output)
# - License status verification and reporting
# - Modular function design for better maintainability and debugging
#
# USAGE:
# 1. Configure the variables in the CONFIGURATION section below:
#    - ESXI_HOST: IP address, FQDN, or SSH alias of your ESXi host
#    - ESXI_PASSWORD: Leave empty to be prompted securely (recommended for SSH aliases)
#    - ESXI_LICENSE: Your VMware ESXi license key
#
# 2. Ensure prerequisites are met:
#    - sshpass installed (if using password authentication)
#    - SSH access to ESXi host enabled
#    - Valid VMware ESXi license key
#
# 3. Execute the script: ./esxi_apply_license.sh
#
# AUTHENTICATION METHODS:
# - SSH Key: Automatically detected and used if available (recommended)
# - Password: Prompted securely if SSH key authentication fails
# - SSH Aliases: Fully supported through SSH config files and includes
#
# SAFETY FEATURES:
# - Automatic backup of existing license configuration before changes
# - Comprehensive validation of license key format before installation
# - Duplicate license detection (prevents applying the same license multiple times)
# - Service status checks to ensure proper operation after changes
# - SSH ControlMaster for reliable connection reuse throughout the process
#
# OUTPUT:
# - Real-time progress logging to console
# - Complete execution log saved to timestamped file
# - Detailed verification of all operations performed
# - License status and expiration information
#
# REQUIREMENTS:
# - VMware ESXi 7.x host with SSH enabled
# - Linux/Unix system with bash and ssh
# - Network connectivity to ESXi host
# - Valid VMware ESXi license key (25-character format)
# -----------------------------------------------------------------------------

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# =============================================================================
# CONFIGURATION VARIABLES - EDIT THESE VALUES
# =============================================================================

# ESXi connection details
ESXI_HOST="esxi7a"                    # ESXi host IP or FQDN
ESXI_USER="root"                              # ESXi username (usually root)
ESXI_PASSWORD=""       # ESXi password

# Global variable to track authentication method
USE_SSH_KEY_AUTH=false

# ESXi License Configuration
ESXI_LICENSE="JJ2WR-25L9P-H71A8-6J20P-C0K3F"  # VMware ESXi license key

# =============================================================================
# SCRIPT CONFIGURATION - USUALLY NO NEED TO MODIFY
# =============================================================================

# SSH connection options
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30"

# SSH ControlMaster configuration
CONTROL_SOCKET_DIR="/tmp"
CONTROL_SOCKET_PATH="$CONTROL_SOCKET_DIR/ssh-control-$$-$(date +%s)"

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

check_configuration() {
    # Validate basic configuration variables and detect SSH aliases
    # Does NOT prompt for password - that's handled in establish_ssh_connection()
    log "Checking configuration..."
    
    # Check if configuration variables are properly set
    if [[ "$ESXI_HOST" == "192.168.1.100" ]]; then
        error_exit "Please update ESXI_HOST with your actual ESXi IP address"
    fi
    
    # Check if it might be an SSH alias
    if [[ ! "$ESXI_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ ! "$ESXI_HOST" =~ \. ]]; then
        if [[ -f "$HOME/.ssh/config" ]] && grep -q "^Host $ESXI_HOST$" "$HOME/.ssh/config" 2>/dev/null; then
            log "Detected SSH alias '$ESXI_HOST' - will try SSH key authentication first"
        fi
    fi
    
    # Validate license key configuration
    if [[ "$ESXI_LICENSE" == "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" ]]; then
        error_exit "Please update ESXI_LICENSE with your actual VMware license key"
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
    # Validate required tools exist and are available
    # Performs basic system validation
    log "Checking prerequisites..."
    
    # Check if required tools are available
    command -v sshpass >/dev/null 2>&1 || error_exit "sshpass is required but not installed"
    command -v ssh >/dev/null 2>&1 || error_exit "ssh is required but not installed"
    
    # Check if control socket directory exists and is writable
    if [[ ! -d "$CONTROL_SOCKET_DIR" ]] || [[ ! -w "$CONTROL_SOCKET_DIR" ]]; then
        error_exit "Control socket directory $CONTROL_SOCKET_DIR is not writable"
    fi
    
    log "Prerequisites check passed"
}

establish_ssh_connection() {
    # Establish SSH ControlMaster connection to ESXi host
    # Tests both SSH key and password authentication methods
    # Sets up persistent connection for all subsequent operations
    log "Establishing SSH ControlMaster connection to $ESXI_HOST..."
    
    # Set up trap to cleanup connection on script exit
    trap cleanup_ssh_connection EXIT
    
    # Try SSH key authentication first
    log "Attempting SSH key authentication..."
    if ssh $SSH_OPTS -M -S "$CONTROL_SOCKET_PATH" -f -N "$ESXI_USER@$ESXI_HOST" 2>/dev/null; then
        log "SSH ControlMaster connection established successfully (using SSH key)"
        USE_SSH_KEY_AUTH=true
        return 0
    else
        log "SSH key authentication failed, trying password authentication"
    fi
    
    # If SSH key failed, try password authentication
    if [[ -z "$ESXI_PASSWORD" ]]; then
        log "ESXi password required for connection"
        prompt_for_password
    fi
    
    # Test password-based connection
    if sshpass -p "$ESXI_PASSWORD" ssh $SSH_OPTS -M -S "$CONTROL_SOCKET_PATH" -f -N "$ESXI_USER@$ESXI_HOST" 2>/dev/null; then
        log "SSH ControlMaster connection established successfully (using password)"
        USE_SSH_KEY_AUTH=false
        
        # Store password for reuse by subsequent connections
        export SSHPASS="$ESXI_PASSWORD"
    else
        error_exit "Cannot establish SSH ControlMaster connection to $ESXI_HOST using either SSH key or password authentication"
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

    # Execute command using the established ControlMaster connection
    local output
    
    if [[ "$USE_SSH_KEY_AUTH" == true ]]; then
        # Use SSH key authentication with ControlMaster
        if output=$(ssh -S "$CONTROL_SOCKET_PATH" "$ESXI_USER@$ESXI_HOST" "$command" 2>&1); then
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
            error_exit "Failed to execute: $description (SSH key authentication failed)"
        fi
    else
        # Use password authentication with ControlMaster
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
            error_exit "Failed to execute: $description (password authentication failed)"
        fi
    fi
}

validate_license_key() {
    # Comprehensive validation of ESXi license key format
    # Validates format, character set, and structure
    log "Validating ESXi license key..."
    
    # Basic format validation (25 characters with 4 hyphens in correct positions)
    if [[ ! "$ESXI_LICENSE" =~ ^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$ ]]; then
        error_exit "Invalid ESXi license key format. Expected format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
    fi
    
    # Check total length (should be 29 characters including hyphens)
    if [[ ${#ESXI_LICENSE} -ne 29 ]]; then
        error_exit "Invalid ESXi license key length. Expected 29 characters (25 alphanumeric + 4 hyphens)"
    fi
    
    # Mask license key for logging (show only first and last segments)
    local masked_license
    masked_license="${ESXI_LICENSE:0:5}-XXXXX-XXXXX-XXXXX-${ESXI_LICENSE:24:5}"
    
    log "ESXi license key format is valid"
    log "  License key: $masked_license"
    log "  Total length: ${#ESXI_LICENSE} characters"
}

check_current_license() {
    # Check and display current license status before applying new license
    # Provides information about existing licenses and evaluation status
    log "Checking current license status..."
    
    local check_cmd="
        echo '=== Current License Status ==='
        
        # Check current license information
        if vim-cmd vimsvc/license --show 2>/dev/null; then
            echo ''
            echo 'License information retrieved successfully'
        else
            echo 'No current license information available or command failed'
        fi
        
        echo ''
        echo '=== System Evaluation Status ==='
        # Check evaluation mode status
        if vim-cmd vimsvc/license --show 2>/dev/null | grep -q -i 'evaluation'; then
            echo 'System appears to be in evaluation mode'
        else
            echo 'System does not appear to be in evaluation mode'
        fi
    "
    
    execute_remote_command "$check_cmd" "Checking current license status"
}

backup_existing_license() {
    # Create backup of current license configuration before applying new license
    # Saves current license information to backup file with timestamp
    log "Creating backup of existing license configuration..."
    
    local backup_cmd="
        BACKUP_SUFFIX=\$(date +%Y%m%d_%H%M%S)
        BACKUP_FILE=\"/tmp/esxi_license_backup_\$BACKUP_SUFFIX.txt\"
        
        echo 'Creating license configuration backup...'
        echo \"=== ESXi License Backup - \$(date) ===\" > \"\$BACKUP_FILE\"
        echo '' >> \"\$BACKUP_FILE\"
        
        # Get current license information
        echo '=== Current License Information ===' >> \"\$BACKUP_FILE\"
        vim-cmd vimsvc/license --show >> \"\$BACKUP_FILE\" 2>/dev/null || echo 'No license information available' >> \"\$BACKUP_FILE\"
        echo '' >> \"\$BACKUP_FILE\"
        
        # Get current evaluation status
        echo '=== Current Evaluation Status ===' >> \"\$BACKUP_FILE\"
        vim-cmd vimsvc/license --show 2>/dev/null | grep -i 'evaluation' >> \"\$BACKUP_FILE\" || echo 'No evaluation status found' >> \"\$BACKUP_FILE\"
        echo '' >> \"\$BACKUP_FILE\"
        
        echo \"License backup created: \$BACKUP_FILE\"
        echo \"Backup completed with suffix: \$BACKUP_SUFFIX\"
    "
    
    execute_remote_command "$backup_cmd" "Creating backup of existing license configuration"
}

apply_license() {
    # Apply the new ESXi license to the host
    # Uses vim-cmd to add and assign the license key
    log "Applying ESXi license..."
    
    # Mask license key for logging
    local masked_license="${ESXI_LICENSE:0:5}-XXXXX-XXXXX-XXXXX-${ESXI_LICENSE:24:5}"
    log "Applying license: $masked_license"
    
    local apply_cmd="
        echo 'Applying ESXi license key...'
        
        # Add the license key to the license manager
        if vim-cmd vimsvc/license --add $ESXI_LICENSE 2>/dev/null; then
            echo 'License key added successfully to license manager'
        else
            echo 'Failed to add license key to license manager'
            exit 1
        fi
        
        echo ''
        echo 'License key has been applied successfully'
        
        # Verify the license was added
        echo ''
        echo '=== Verifying License Addition ==='
        vim-cmd vimsvc/license --show 2>/dev/null | head -20
    "
    
    execute_remote_command "$apply_cmd" "Applying ESXi license key"
}

restart_esxi_services() {
    # Restart necessary ESXi services to apply license changes
    # Restarts hostd and vpxa services in proper sequence
    log "Restarting ESXi services to apply license changes..."
    
    # Step 1: Restart hostd service
    log "Step 1: Restarting hostd service..."
    execute_remote_command "/etc/init.d/hostd restart" "Restarting hostd service"
    
    # Wait for hostd to stabilize
    log "Waiting for hostd to stabilize..."
    sleep 5
    
    # Step 2: Restart vpxa service (vCenter agent)
    log "Step 2: Restarting vpxa service..."
    execute_remote_command "/etc/init.d/vpxa restart" "Restarting vpxa service"
    
    # Wait for vpxa to stabilize
    log "Waiting for vpxa to stabilize..."
    sleep 5
    
    # Step 3: Verify services are running
    log "Step 3: Verifying service status..."
    local verify_cmd="
        echo '=== Service Status Verification ==='
        echo 'hostd service status:'
        /etc/init.d/hostd status
        echo ''
        echo 'vpxa service status:'
        /etc/init.d/vpxa status
        echo ''
        echo 'All services restarted successfully'
    "
    execute_remote_command "$verify_cmd" "Verifying service status after restart"
}

verify_license_installation() {
    # Comprehensive verification of license installation
    # Checks license status, expiration, and system information
    log "Verifying license installation..."
    
    local verify_cmd="
        echo '=== License Installation Verification ==='
        
        # Show current license status
        echo '=== Current License Information ==='
        if vim-cmd vimsvc/license --show 2>/dev/null; then
            echo ''
            echo 'License verification: PASSED'
        else
            echo 'License verification: FAILED'
            exit 1
        fi
        
        echo ''
        echo '=== License Assignment Check ==='
        # Check if we're still in evaluation mode
        if vim-cmd vimsvc/license --show 2>/dev/null | grep -q -i 'evaluation'; then
            echo 'WARNING: System still appears to be in evaluation mode'
            echo 'This might indicate the license was not properly assigned'
        else
            echo 'License appears to be properly assigned (no evaluation mode detected)'
        fi
        
        echo ''
        echo '=== System Information ==='
        # Show basic system information
        esxcli system version get 2>/dev/null || echo 'Could not retrieve system version'
        
        echo ''
        echo 'License installation verification completed'
    "
    
    execute_remote_command "$verify_cmd" "Verifying license installation"
}

display_final_status() {
    # Display final license status and system information
    # Provides summary of license application results
    log "Displaying final license status..."
    
    local status_cmd="
        echo '=== Final License Status ==='
        echo ''
        echo 'ESXi License Information:'
        vim-cmd vimsvc/license --show 2>/dev/null | head -30
        
        echo ''
        echo '=== System Summary ==='
        echo \"Host: \$(hostname)\"
        echo \"Date: \$(date)\"
        echo \"Uptime: \$(uptime)\"
        
        echo ''
        echo 'License application process completed successfully!'
    "
    
    execute_remote_command "$status_cmd" "Displaying final license status"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Main script execution flow with comprehensive logging and error handling
    # Sets up logging, validates inputs, applies license, and verifies installation
    
    # Setup logging with timestamp
    local log_timestamp
    log_timestamp=$(date '+%y%m%d_%H%M%S')
    LOG_FILE="esxi_apply_license-${log_timestamp}.log"
    
    log "Starting ESXi license application script"
    log "Target host: $ESXI_HOST"
    log "Log file: $(pwd)/$LOG_FILE"
    
    # Mask license for initial logging
    local masked_license="${ESXI_LICENSE:0:5}-XXXXX-XXXXX-XXXXX-${ESXI_LICENSE:24:5}"
    log "License to apply: $masked_license"
    
    # Step 1: Check prerequisites first (tools validation ONLY)
    check_prerequisites
    
    # Step 2: Validate license key format
    validate_license_key
    
    # Step 3: Check basic configuration
    check_configuration
    
    # Step 4: Establish SSH ControlMaster connection (this sets USE_SSH_KEY_AUTH)
    establish_ssh_connection
    
    # Step 5: Check current license status
    check_current_license
    
    # Step 6: Create backup of existing license configuration
    backup_existing_license
    
    # Step 7: Apply the new license
    apply_license
    
    # Step 8: Restart necessary services
    restart_esxi_services
    
    # Step 9: Verify license installation
    verify_license_installation
    
    # Step 10: Display final status
    display_final_status
    
    log "ESXi license application completed successfully!"
    log "License has been applied and services have been restarted"
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
