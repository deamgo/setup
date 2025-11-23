#!/bin/bash
# feature:auto renew https certs

CERTS_DIR="/apps/share/certs"
CONFIG_FILE="$CERTS_DIR/domain_records.csv"
ACME_DIR="/apps/share/acme-challenge"
ACME_INSTALL_DIR="/apps/acme"
EMAIL="ops@deamgo.com"
LOG_FILE="$CERTS_DIR/https.log"
SCRIPT_PATH=$(realpath "$0")
ACME_LOG_DIR="$CERTS_DIR/acme-logs"
RELOAD_CMD="docker exec gateway nginx -s reload"

if [ -d "$ACME_INSTALL_DIR" ] && [ -f "$ACME_INSTALL_DIR/acme.sh.env" ]; then
    source "$ACME_INSTALL_DIR/acme.sh.env"
fi

# Log function
log() {
    local timestamp=$(date "+%a %b %d %I:%M:%S %p %Z %Y")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Check and install required dependencies
install_dependencies() {
    log "Checking for required dependencies..."

    # Check for socat
    if ! command -v socat >/dev/null 2>&1; then
        log "Installing socat..."

        # Detect package manager and install socat
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y socat
        elif command -v yum >/dev/null 2>&1; then
            yum install -y socat
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y socat
        elif command -v apk >/dev/null 2>&1; then
            apk add --no-cache socat
        else
            log "WARNING: Could not install socat automatically. Please install it manually."
            return 1
        fi

        log "Socat installed successfully"
    else
        log "Socat is already installed"
    fi

    return 0
}

# init dirs
init() {
    [ -d "$CERTS_DIR" ] || mkdir -p "$CERTS_DIR"
    [ -d "$ACME_LOG_DIR" ] || mkdir -p "$ACME_LOG_DIR"
    [ -f "$CONFIG_FILE" ] || printf "domain,renew_date,cert_dir,status\n" > "$CONFIG_FILE"
    [ -d "$ACME_DIR" ] || mkdir -p "$ACME_DIR"

    # Ensure log file exists with proper permissions
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
}

# install acme
install_acme() {
    # Install dependencies first
    install_dependencies

    if [ ! -d "$ACME_INSTALL_DIR" ]; then
        log "Installing acme.sh..."

        # Create the parent directory if it doesn't exist
        mkdir -p "$(dirname "$ACME_INSTALL_DIR")"

        # Install acme.sh to the specified directory
        curl https://get.acme.sh | sh -s email="$EMAIL" --home "$ACME_INSTALL_DIR" --force --nocron

        # Check if installation was successful
        if [ ! -f "$ACME_INSTALL_DIR/acme.sh" ]; then
            log "ERROR: acme.sh installation failed!"
            return 1
        fi

        source "$ACME_INSTALL_DIR/acme.sh.env"

        # Configure acme.sh
        run_acme "install" --set-default-ca --server letsencrypt

        log "acme.sh installation completed successfully"
    else
        log "acme.sh already installed at $ACME_INSTALL_DIR"

        # Ensure acme.sh is properly configured even if already installed
        if [ -f "$ACME_INSTALL_DIR/acme.sh" ]; then
            run_acme "install" --set-default-ca --server letsencrypt >/dev/null 2>&1
        else
            log "WARNING: acme.sh directory exists but executable not found!"
        fi
    fi

    return 0
}

# Create a new function to run acme commands with logging
run_acme() {
    local domain=$1
    shift
    local log_file="$ACME_LOG_DIR/$domain-$(date +%Y%m%d%H%M%S).log"

    log "Running acme.sh command for $domain: $*"
    log "Full acme.sh output will be logged to $log_file"

    # Run the command, capturing output to the acme log file
    "$ACME_INSTALL_DIR/acme.sh" "$@" 2>&1 | tee -a "$log_file"

    return ${PIPESTATUS[0]}
}

# add domain record
add_domain() {
    local domain=$1
    local cert_dir="$CERTS_DIR/$domain"

    # Create cert directory if it doesn't exist
    [ -d "$cert_dir" ] || mkdir -p "$cert_dir"

    # check duplicate record
    if grep -q "^$domain," "$CONFIG_FILE"; then
        log "Error: domain $domain already exists"
        exit 1
    fi

    # issue new cert
    log "Issuing cert for $domain..."
    run_acme "$domain" --issue -d "$domain" -w "$ACME_DIR"
    local issue_exit_code=$?

    if [ $issue_exit_code -ne 0 ]; then
        log "ERROR: Failed to issue certificate for $domain"
        return 1
    fi

    # install cert to the specified location
    log "Installing cert for $domain to $cert_dir..."
    run_acme "$domain" --install-cert -d "$domain" \
        --fullchain-file "$cert_dir/fullchain.pem" \
        --key-file "$cert_dir/privkey.pem" \
        --reloadcmd "$RELOAD_CMD"
    local install_exit_code=$?

    if [ $install_exit_code -ne 0 ]; then
        log "ERROR: Failed to install certificate for $domain"
        return 1
    fi

    chmod 600 "$cert_dir/fullchain.pem" "$cert_dir/privkey.pem"

    # record issue info
    local renew_date=$(date -d "+90 days" "+%Y-%m-%d")
    printf "%s,%s,%s,valid\n" "$domain" "$renew_date" "$cert_dir" >> "$CONFIG_FILE"
    log "Cert installed to: $cert_dir"

    return 0
}

# Force renew a specific domain
renew() {
    local domain=$1
    local domain_info=$(grep "^$domain," "$CONFIG_FILE")

    if [ -z "$domain_info" ]; then
        log "Error: domain $domain not found in config"
        return 1
    fi

    # Extract domain info
    IFS=, read -r _ renew_date cert_dir status <<< "$domain_info"

    # Create cert directory if it doesn't exist
    [ -d "$cert_dir" ] || mkdir -p "$cert_dir"

    log "Force renewing domain $domain..."

    # execute renew
    run_acme "$domain" --renew -d "$domain" --force
    local renew_exit_code=$?

    if [ $renew_exit_code -ne 0 ]; then
        sed -i "/^$domain,/s/,valid$/,invalid/" "$CONFIG_FILE"
        log "WARNING: $domain renewal failed!"
        return 1
    fi

    # install renewed cert to the specified location
    log "Installing renewed cert for $domain to $cert_dir..."
    run_acme "$domain" --install-cert -d "$domain" \
        --fullchain-file "$cert_dir/fullchain.pem" \
        --key-file "$cert_dir/privkey.pem" \
        --reloadcmd "$RELOAD_CMD"
    local install_exit_code=$?

    if [ $install_exit_code -ne 0 ]; then
        sed -i "/^$domain,/s/,valid$/,invalid/" "$CONFIG_FILE"
        log "ERROR: Failed to install renewed certificate for $domain"
        return 1
    fi

    chmod 600 "$cert_dir/fullchain.pem" "$cert_dir/privkey.pem"

    # update record
    local new_renew_date=$(date -d "+90 days" "+%Y-%m-%d")
    sed -i "/^$domain,/s/,$renew_date,/,$new_renew_date,/" "$CONFIG_FILE"
    log "Renewal success! New expire date: $new_renew_date"

    return 0
}

# renew check and execute
renew_check() {
    local current_ts=$(date +%s)
    log "Starting certificate renewal check"

    while IFS=, read -r domain renew_date cert_dir status
    do
        # skip title line
        [ "$domain" = "domain" ] && continue

        # calculate days until expiry
        local renew_ts=$(date -d "$renew_date" +%s)
        local days_since_last_renewal=$(( (renew_ts - current_ts) / 86400 ))

        log "Domain $domain has $days_since_last_renewal days since last renewal"

        # Changed logic: renew when MORE than 60 days since last renewal
        if [ $days_since_last_renewal -gt 60 ]; then
            log "Domain $domain eligible for renewal (days since last renewal: $days_since_last_renewal)..."
            renew "$domain"
        else
            log "Domain $domain not renewed (less than or equal to 60 days since last renewal)"
        fi
    done < "$CONFIG_FILE"

    log "Certificate renewal check completed"
}

# Add to cron for daily checks
setup_cron() {
    log "Setting up cron job for daily certificate checks"

    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
        log "Cron job already exists"
    else
        # Add new cron job - run at 2:30 AM daily
        (crontab -l 2>/dev/null; echo "30 2 * * * $SCRIPT_PATH renew-check") | crontab -
        log "Added cron job to run daily at 2:30 AM"
    fi
}

# main logic
case "$1" in
    add)
        [ $# -eq 2 ] || { echo "Usage: $0 add <domain>"; exit 1; }
        init
        install_acme
        add_domain "$2"
        ;;
    renew-check)
        init
        renew_check
        ;;
    renew)
        [ $# -eq 2 ] || { echo "Usage: $0 renew <domain>"; exit 1; }
        init
        renew "$2"
        ;;
    list)
        init
        column -t -s, "$CONFIG_FILE"
        ;;
    setup-cron)
        init
        setup_cron
        ;;
    *)
        echo "usage:"
        echo "  $0 add <domain>          add new cert"
        echo "  $0 renew-check           execute renew check for all domains"
        echo "  $0 renew <domain>        force renew a specific domain"
        echo "  $0 list                  view cert list"
        echo "  $0 setup-cron            add script to cron for daily checks"
        exit 1
        ;;
esac

log "Command '$1' completed"