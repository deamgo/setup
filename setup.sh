#!/bin/bash

# Exit on any error
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTO_HTTPS_TARGET="/usr/local/bin/https"

# Status tracking for installation and rollback
STATUS_FILE="/var/log/setup.log"
ROLLBACK_LOG="/var/log/setup-rollback.log"
DEFAULT_BACKUP_DIR="/apps/backups"
BACKUP_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root"
    exit 1
fi

# Interactive configuration
safe_read() {
    local prompt="$1"
    local default="$2"
    local result
    if [ -t 0 ]; then
        read -p "${prompt}" result || true
    else
        # Non-interactive mode: use default
        result=""
    fi
    echo "${result:-${default}}"
}

get_user_input() {
    local prompt="$1"
    local default="$2"
    safe_read "${prompt} [${default}]: " "${default}"
}

get_password() {
    local prompt="$1"
    local default="$2"
    local password1
    local password2

    # In non-interactive mode, use default or generate
    if [ ! -t 0 ]; then
        if [ -n "$default" ]; then
            echo -n "$default"
        else
            echo -n "$(generate_password)"
        fi
        echo >&2  # Add newline to stderr for proper terminal formatting
        return
    fi

    while true; do
        # If default password is provided and user presses Enter, use default
        if [ -n "$default" ]; then
            read -s -p "${prompt} [press Enter to use default: ${default}]: " password1 || true
            echo
            if [ -z "$password1" ]; then
                # Return the default password if user pressed Enter
                echo -n "$default"  # Use -n to avoid adding newline to output
                echo >&2  # Add newline to stderr for proper terminal formatting
                return
            fi
        else
            read -s -p "${prompt}: " password1 || true
            echo
            if [ -z "$password1" ]; then
                echo "Password cannot be empty. Please try again."
                continue
            fi
        fi

        read -s -p "Confirm password: " password2 || true
        echo

        if [ "$password1" = "$password2" ]; then
            if [ ${#password1} -lt 8 ]; then
                echo "Password must be at least 8 characters long"
                continue
            fi
            echo -n "$password1"  # Use -n to avoid adding newline to output
            echo >&2  # Add newline to stderr for proper terminal formatting
            break
        else
            echo "Passwords do not match. Please try again."
        fi
    done
}

# Function to generate a random password
generate_password() {
    # Only use alphanumeric characters (letters and numbers)
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

# Interactive configuration
configure_settings() {
    log "Starting interactive configuration..."

    # SSH Port configuration
    while true; do
        NEW_SSH_PORT=$(get_user_input "Enter new SSH port" "39022")
        if [[ "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] && [ "$NEW_SSH_PORT" -ge 1024 ] && [ "$NEW_SSH_PORT" -le 65535 ]; then
            break
        else
            error "Please enter a valid port number between 1024 and 65535"
        fi
    done

    # SSH security configuration
    DISABLE_ROOT_LOGIN=$(safe_read "Do you want to disable root login? (y/n) [y]: " "y")

    DISABLE_PASSWORD_AUTH=$(safe_read "Do you want to disable password authentication (use only SSH keys)? (y/n) [y]: " "y")

    log "Please enter root password:"
    RESET_ROOT_PASSWORD=$(safe_read "Do you want to reset root password? (y/n) [n]: " "n")

    if [[ "${RESET_ROOT_PASSWORD}" =~ ^[Yy]$ ]]; then
        ROOT_PASSWORD=$(get_password "Enter new root password" "$(generate_password)")
    else
        ROOT_PASSWORD="<keep existing>"
    fi

    # UIPaaS admin user configuration
    UIPAAS_ADMIN=$(get_user_input "Enter UIPaaS admin username" "ops")
    UIPAAS_ADMIN_PASSWORD=$(get_password "Enter ${UIPAAS_ADMIN} password" "$(generate_password)")

    # Docker registry mirror configuration
    echo -e "\nSelect Docker registry mirror:"
    echo "1) Aliyun (registry.cn-hangzhou.aliyuncs.com)"
    echo "2) Tencent Cloud (mirror.ccs.tencentyun.com)"
    echo "3) DaoCloud (f1361db2.m.daocloud.io)"
    echo "4) NetEase (hub-mirror.c.163.com)"
    echo "5) Custom mirror"
    echo "6) No mirror (use Docker default)"

    DOCKER_MIRROR_CHOICE=$(safe_read "Enter your choice [1]: " "1")

    case $DOCKER_MIRROR_CHOICE in
        1)
            DOCKER_MIRROR="https://registry.cn-hangzhou.aliyuncs.com"
            ;;
        2)
            DOCKER_MIRROR="https://mirror.ccs.tencentyun.com"
            ;;
        3)
            DOCKER_MIRROR="https://f1361db2.m.daocloud.io"
            ;;
        4)
            DOCKER_MIRROR="https://hub-mirror.c.163.com"
            ;;
        5)
            DOCKER_MIRROR=$(safe_read "Enter custom Docker mirror URL: " "")
            ;;
        6)
            DOCKER_MIRROR=""
            ;;
        *)
            DOCKER_MIRROR="https://mirror.ccs.tencentyun.com"
            warning "Invalid choice, using default (Tencent Cloud)"
            ;;
    esac

    # PostgreSQL installation configuration
    INSTALL_POSTGRES=$(safe_read "Do you want to install PostgreSQL? (y/n) [y]: " "y")
    if [[ "${INSTALL_POSTGRES}" =~ ^[Yy]$ ]]; then
        BACKUP_DIR=$(get_user_input "Enter base directory for PostgreSQL backups" "${DEFAULT_BACKUP_DIR}")
    else
        BACKUP_DIR=""
    fi

    # Confirm settings
    echo -e "\n=== Configuration Summary ==="
    echo "New SSH Port: ${NEW_SSH_PORT}"
    echo "UIPaaS Admin: ${UIPAAS_ADMIN}"
    if [ -n "${DOCKER_MIRROR}" ]; then
        echo "Docker Mirror: ${DOCKER_MIRROR}"
    else
        echo "Docker Mirror: None (using Docker default)"
    fi
    if [[ "${INSTALL_POSTGRES}" =~ ^[Yy]$ ]]; then
        echo "PostgreSQL: Install"
        if [ -n "${BACKUP_DIR}" ]; then
            echo "PostgreSQL Backup Directory: ${BACKUP_DIR}"
        else
            echo "PostgreSQL Backup Directory: /apps/backups/postgres (default)"
        fi
    else
        echo "PostgreSQL: Not install"
    fi

    CONFIRM=$(safe_read "Are these settings correct? (y/n) [y]: " "y")

    if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
        error "Configuration cancelled. Please run the script again."
        exit 1
    fi
}

# 1. Docker Installation
install_docker() {
    log "Installing Docker..."

    # Remove old versions if exist
    apt-get remove -y docker docker-engine docker.io containerd runc || true

    # Install prerequisites
    apt-get update
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    # Add Docker's official GPG key
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    # Set up the repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Configure mirror for Docker if specified
    if [ -n "${DOCKER_MIRROR}" ]; then
        mkdir -p /etc/docker
        cat > /etc/docker/daemon.json <<EOF
{
    "registry-mirrors": ["${DOCKER_MIRROR}"]
}
EOF
        log "Docker configured with mirror: ${DOCKER_MIRROR}"
    else
        log "Docker configured with default registry (no mirror)"
    fi

    # Install Docker Engine
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io

    # Start and enable Docker
    systemctl start docker
    systemctl enable docker

    log "Docker installed successfully"
    save_status "docker_installed"
}

# 2. User Configuration
configure_users() {
    log "Configuring users..."

    # Set root password only if requested
    if [[ "${ROOT_PASSWORD}" != "<keep existing>" ]]; then
        # Ensure no newlines in password
        ROOT_PASSWORD=$(echo -n "${ROOT_PASSWORD}" | tr -d '\n')
        log "Setting root password (length: ${#ROOT_PASSWORD})"
        echo "root:${ROOT_PASSWORD}" | chpasswd
        log "Root password has been updated"
    else
        log "Root password remains unchanged"
    fi

    # Create admin user
    useradd -m -s /bin/bash "${UIPAAS_ADMIN}" || true

    # Ensure no newlines in admin password
    UIPAAS_ADMIN_PASSWORD=$(echo -n "${UIPAAS_ADMIN_PASSWORD}" | tr -d '\n')
    log "Setting password for ${UIPAAS_ADMIN} (length: ${#UIPAAS_ADMIN_PASSWORD})"
    echo "${UIPAAS_ADMIN}:${UIPAAS_ADMIN_PASSWORD}" | chpasswd
    log "Password set successfully for ${UIPAAS_ADMIN}"

    # Add admin user to docker group
    usermod -aG docker "${UIPAAS_ADMIN}"

    # Generate SSH keys for admin user
    mkdir -p /home/${UIPAAS_ADMIN}/.ssh
    ssh-keygen -t ed25519 -f /home/${UIPAAS_ADMIN}/.ssh/id_ed25519 -N ""

    # Configure authorized_keys
    cat /home/${UIPAAS_ADMIN}/.ssh/id_ed25519.pub > /home/${UIPAAS_ADMIN}/.ssh/authorized_keys
    chmod 600 /home/${UIPAAS_ADMIN}/.ssh/authorized_keys
    chmod 700 /home/${UIPAAS_ADMIN}/.ssh
    chown -R ${UIPAAS_ADMIN}:${UIPAAS_ADMIN} /home/${UIPAAS_ADMIN}/.ssh

    log "User configuration completed"
    save_status "users_configured"
}

# 3. SSH Configuration
configure_ssh() {
    log "Configuring SSH..."

    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

    # Configure SSH
    cat > /etc/ssh/sshd_config <<EOF
Port ${NEW_SSH_PORT}
Port 22

Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Security settings
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
$(if [[ "${DISABLE_PASSWORD_AUTH}" =~ ^[Yy]$ ]]; then echo "PasswordAuthentication no"; else echo "PasswordAuthentication yes"; fi)
$(if [[ "${DISABLE_ROOT_LOGIN}" =~ ^[Yy]$ ]]; then echo "PermitRootLogin no"; else echo "PermitRootLogin yes"; fi)

# Connection settings
ClientAliveInterval 60
ClientAliveCountMax 3

# Other settings
UsePAM yes
X11Forwarding yes
PrintMotd no

AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    # Test SSH configuration
    sshd -t || {
        error "SSH configuration test failed"
        mv /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
        exit 1
    }

    # Restart SSH service more thoroughly
    log "Stopping SSH service..."
    systemctl stop ssh

    # Small delay to ensure complete shutdown
    sleep 2

    log "Starting SSH service with new configuration..."
    systemctl start ssh

    # Verify SSH is running
    if systemctl is-active --quiet ssh; then
        log "SSH service restarted successfully"
    else
        error "Failed to restart SSH service. Attempting to restore original configuration..."
        mv /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
        systemctl start ssh
        if systemctl is-active --quiet ssh; then
            warning "Restored original SSH configuration"
        else
            error "Could not restore SSH service. Manual intervention required."
        fi
        exit 1
    fi

    # Test if the new SSH port is open and accessible
    log "Testing SSH port connectivity..."

    # Install netcat if not available
    if ! command -v nc &> /dev/null; then
        log "Installing netcat for port testing..."
        apt-get update -qq && apt-get install -y -qq netcat
    fi

    # Test using netcat
    if nc -z -v -w5 127.0.0.1 ${NEW_SSH_PORT} 2>&1; then
        log "SSH port ${NEW_SSH_PORT} is open and accessible via netcat"
    else
        warning "Could not connect to SSH port ${NEW_SSH_PORT} using netcat"
    fi

    # Verify SSH daemon is listening on the new port
    if ss -tln | grep ":${NEW_SSH_PORT}"; then
        log "SSH daemon is listening on port ${NEW_SSH_PORT}"
    else
        warning "SSH daemon does not appear to be listening on port ${NEW_SSH_PORT}"
        log "Current listening ports:"
        ss -tunlp | grep "LISTEN" | grep "sshd"
    fi

    log "SSH configured successfully"
    save_status "ssh_configured"

    # Warning about SSH settings
    if [[ "${DISABLE_PASSWORD_AUTH}" =~ ^[Yy]$ ]]; then
        warning "Password authentication is disabled. Make sure you have saved the SSH private key!"
    fi
    if [[ "${DISABLE_ROOT_LOGIN}" =~ ^[Yy]$ ]]; then
        warning "Root login is disabled. You must use '${UIPAAS_ADMIN}' user to login and then use 'sudo' for root access."
    fi
}

# Setup UIPaaS directories
setup_uipaas_dirs() {
    log "Setting up UIPaaS directories..."

    # Create main directory structure
    mkdir -p /apps/share/certs
    mkdir -p /apps/share/html
    mkdir -p /apps/share/acme-challenge
    mkdir -p /apps/conf/sites-enabled
    mkdir -p /apps/backups
    mkdir -p /apps/uipaas

    # Set ownership so admin user can operate UIPaaS deployment directory
    chown -R ${UIPAAS_ADMIN}:${UIPAAS_ADMIN} /apps/uipaas

    # Apply reasonable permissions
    chmod 755 /apps/uipaas
    chmod 750 /apps/share/certs
    chmod 755 /apps/share/html
    chmod 755 /apps/share/acme-challenge
    chmod 755 /apps/conf
    chmod 755 /apps/conf/sites-enabled
    chmod 755 /apps/backups

    # Create symbolic link in admin user's home
    ln -sfn /apps/uipaas /home/${UIPAAS_ADMIN}/uipaas

    log "UIPaaS directories setup completed"
    save_status "directories_created"
}

# Install and configure PostgreSQL
install_postgres() {
    # Check if PostgreSQL installation is requested
    if [[ ! "${INSTALL_POSTGRES}" =~ ^[Yy]$ ]]; then
        log "PostgreSQL installation skipped by user"
        return 0
    fi

    log "Installing PostgreSQL..."

    # Create Docker network if it doesn't exist
    log "Creating uipaas_network..."
    docker network inspect uipaas_network >/dev/null 2>&1 || docker network create uipaas_network
    save_status "network_created"

    # Set PostgreSQL variables
    PG_USER=$(get_user_input "Enter PostgreSQL username" "uipaas_owner")
    PG_PASSWORD=$(generate_password)
    PG_DB="uipaas"
    PG_PORT="5432"
    PG_VOLUME="/var/lib/postgresql/data"
    PG_VERSION="17"

    # Create PostgreSQL volume
    docker volume create postgres_data

    # Run PostgreSQL container
    docker run -d \
        --name postgres \
        --restart always \
        --network uipaas_network \
        -e POSTGRES_USER=${PG_USER} \
        -e POSTGRES_PASSWORD=${PG_PASSWORD} \
        -e POSTGRES_DB=${PG_DB} \
        -v postgres_data:${PG_VOLUME} \
        postgres:${PG_VERSION}

    # Wait for PostgreSQL to start
    log "Waiting for PostgreSQL to start..."
    sleep 10

    # Create .env file with connection info
    cat > /apps/uipaas/.env <<EOF
# PostgreSQL Connection Information
DATABASE_URL=postgresql://${PG_USER}:${PG_PASSWORD}@postgres:${PG_PORT}/${PG_DB}
EOF

    # Set permissions for .env file
    chown ${UIPAAS_ADMIN}:${UIPAAS_ADMIN} /apps/uipaas/.env
    chmod 600 /apps/uipaas/.env

    # Ask about backup
    SETUP_BACKUP=$(safe_read "Do you want to set up automated PostgreSQL backups? (y/n) [y]: " "y")

    if [[ "${SETUP_BACKUP}" =~ ^[Yy]$ ]]; then
        if [ -n "${BACKUP_DIR}" ]; then
            PG_BACKUP_DIR="${BACKUP_DIR}/postgres_backups"
        else
            PG_BACKUP_DIR="/apps/backups/postgres"
        fi
        log "Using ${PG_BACKUP_DIR} for PostgreSQL backups"

        mkdir -p "${PG_BACKUP_DIR}"
        chmod 750 "${PG_BACKUP_DIR}"

        # Create backup script
        cat > /usr/local/bin/pgback <<EOF
#!/bin/bash
BACKUP_DIR=${PG_BACKUP_DIR}
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)
BACKUP_FILE=\${BACKUP_DIR}/${PG_DB}_\${TIMESTAMP}.sql.gz

# Create backup directory if it doesn't exist
mkdir -p \${BACKUP_DIR}

# Create backup
docker exec postgres pg_dump -U ${PG_USER} ${PG_DB} | gzip > \${BACKUP_FILE}

# Check if backup was successful
if [ \$? -eq 0 ]; then
    echo "Backup created successfully: \${BACKUP_FILE}"

    # Keep only the last 7 backups
    ls -t \${BACKUP_DIR}/${PG_DB}_*.sql.gz | tail -n +8 | xargs -r rm
else
    echo "Error creating backup"
    exit 1
fi
EOF

        chmod +x /usr/local/bin/pgback

        # Set up cron job for daily backup
        echo "0 2 * * * root /usr/local/bin/pgback >> /var/log/postgres_backup.log 2>&1" > /etc/cron.d/postgres_backup
        chmod 644 /etc/cron.d/postgres_backup

        # Create an empty log file
        touch /var/log/postgres_backup.log
        chmod 644 /var/log/postgres_backup.log

        log "PostgreSQL backup configured to run daily at 2:00 AM"
        log "Backup location: ${PG_BACKUP_DIR}"
        log "Backup logs: /var/log/postgres_backup.log"
    fi

    log "PostgreSQL ${PG_VERSION} installed and configured successfully"
    save_status "postgres_installed"
}

install_nginx() {
    log "Setting up Nginx gateway container..."

    local nginx_conf_src="${SCRIPT_DIR}/nginx/nginx.conf"
    local default_conf_src="${SCRIPT_DIR}/nginx/default.conf"
    local auto_https_src="${SCRIPT_DIR}/https.sh"
    local certs_dir="/apps/share/certs"
    local html_dir="/apps/share/html"

    if [ ! -d "$certs_dir" ] || [ ! -d "$html_dir" ] || [ ! -d "/apps/conf" ]; then
        error "Required directories are missing. Please run setup_uipaas_dirs first."
        exit 1
    fi

    if [ ! -f "$nginx_conf_src" ] || [ ! -f "$default_conf_src" ]; then
        error "Nginx template files not found in ${SCRIPT_DIR}/nginx"
        exit 1
    fi

    cp "$nginx_conf_src" /apps/conf/nginx.conf
    cp "$default_conf_src" /apps/conf/default.conf
    chmod 644 /apps/conf/nginx.conf /apps/conf/default.conf

    if [ -f "$auto_https_src" ]; then
        install -m 755 "$auto_https_src" "${AUTO_HTTPS_TARGET}"
    else
        warning "https.sh not found at ${SCRIPT_DIR}, skipping copy"
    fi

    for html in "${SCRIPT_DIR}"/nginx/*.html; do
        [ -f "$html" ] || continue
        cp "$html" /apps/share/html/
    done
    chown -R root:root /apps/share/html
    chmod 755 /apps/share/html
    find /apps/share/html -type f -exec chmod 644 {} \; >/dev/null 2>&1 || true

    docker network inspect uipaas_network >/dev/null 2>&1 || docker network create uipaas_network

    docker rm -f gateway >/dev/null 2>&1 || true
    docker run -d \
        --name gateway \
        --restart on-failure:5 \
        --network uipaas_network \
        -p 80:80 \
        -p 443:443 \
        -v /apps/share:/usr/share/nginx \
        -v /apps/conf/nginx.conf:/etc/nginx/nginx.conf \
        -v /apps/conf/default.conf:/etc/nginx/conf.d/default.conf \
        -v /apps/conf/sites-enabled:/etc/nginx/sites-enabled \
        --label com.centurylinklabs.watchtower.enable=false \
        nginx:alpine
    log "Nginx gateway container is running"
    save_status "nginx_installed"
}

configure_auto_https() {
    local auto_https_bin="${AUTO_HTTPS_TARGET}"
    if [ ! -x "$auto_https_bin" ]; then
        warning "https.sh not found or not executable. Skipping HTTPS configuration."
        return
    fi

    CONFIGURE_HTTPS_NOW=$(safe_read "Do you want to configure HTTPS certificates now? (y/n) [n]: " "n")
    if [[ ! "${CONFIGURE_HTTPS_NOW}" =~ ^[Yy]$ ]]; then
        return
    fi

    if ! command -v dig >/dev/null 2>&1; then
        log "Installing dnsutils for domain resolution checks..."
        apt-get update -qq && apt-get install -y -qq dnsutils
    fi

    while true; do
        TARGET_DOMAIN=$(safe_read "Enter the domain to issue a certificate for (e.g., example.com): " "")
        TARGET_DOMAIN=$(echo -n "$TARGET_DOMAIN" | tr -d '[:space:]')

        if [ -z "$TARGET_DOMAIN" ]; then
            warning "Domain cannot be empty. Please try again."
            continue
        fi

        local resolved_ips=""
        if command -v dig >/dev/null 2>&1; then
            resolved_ips=$(dig +short A "$TARGET_DOMAIN" 2>/dev/null | tr '\n' ' ')
        fi

        if [ -n "$resolved_ips" ] && [ -n "$PUBLIC_IP" ] && [[ "$resolved_ips" != *"$PUBLIC_IP"* ]]; then
            warning "Domain $TARGET_DOMAIN does not appear to resolve to ${PUBLIC_IP} (resolved: ${resolved_ips})."
            CONTINUE_ACME=$(safe_read "Continue anyway? (y/n) [n]: " "n")
            if [[ ! "${CONTINUE_ACME}" =~ ^[Yy]$ ]]; then
                TRY_ANOTHER=$(safe_read "Do you want to enter a different domain? (y/n) [y]: " "y")
                if [[ ! "${TRY_ANOTHER}" =~ ^[Yy]$ ]]; then
                    break
                fi
                continue
            fi
        else
            log "Domain $TARGET_DOMAIN resolves to: ${resolved_ips:-unknown}. Make sure DNS already points to this server."
        fi

        log "Issuing certificate for ${TARGET_DOMAIN}..."
        if "$auto_https_bin" add "$TARGET_DOMAIN"; then
            log "Certificate request for ${TARGET_DOMAIN} completed."
        else
            warning "Failed to issue certificate for ${TARGET_DOMAIN}. Check logs in /apps/share/certs."
        fi

        ANOTHER_DOMAIN=$(safe_read "Do you want to add another domain? (y/n) [n]: " "n")
        if [[ ! "${ANOTHER_DOMAIN}" =~ ^[Yy]$ ]]; then
            break
        fi
    done
}

# Function to detect server's public IP
detect_public_ip() {
    log "Detecting server's public IP address..."

    # Try multiple services to get public IP
    PUBLIC_IP=""

    # Method 1: ifconfig.me
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null)
    fi

    # Method 2: ipinfo.io
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null)
    fi

    # Method 3: api.ipify.org
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null)
    fi

    # Method 4: icanhazip.com
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP=$(curl -s icanhazip.com 2>/dev/null)
    fi

    # If all methods fail, use localhost
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP="<SERVER_IP>"
        warning "Could not detect public IP address. Please replace <SERVER_IP> with your server's IP address."
    else
        log "Detected public IP: $PUBLIC_IP"
    fi
}

# 4. Install 1Panel
install_1panel() {
    log "Installing 1Panel..."

    # Download 1Panel installation script
    curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh
    chmod +x quick_start.sh

    # Create a temporary file to capture installation output
    INSTALL_LOG=$(mktemp)

    # Run 1Panel installation interactively and capture output
    log "Starting 1Panel installation - please follow the prompts"
    log "NOTE: The installation directory setting in our script may not be honored by 1Panel installer"
    log "      Please note where 1Panel is actually installed during the process"

    # Run the installation script and capture all output
    ./quick_start.sh 2>&1 | tee "$INSTALL_LOG"

    # Extract password from installation log - this is the most important part
    # Look for patterns in different languages
    # English: "Panel password: xxxxx"
    # Chinese: "面板密码: xxxxx"
    # Persian: "ramz oboor panel: xxxxx"
    # Portuguese: "Senha do painel: xxxxx"
    # Russian: "Пароль панели: xxxxx"
    PANEL_PASSWORD=$(grep -E '(Panel password|面板密码|ramz oboor panel|Senha do painel|Пароль панели)[ \t]*:' "$INSTALL_LOG" | tail -n 1 | awk -F':' '{print $NF}' | tr -d ' ')

    # Check if 1pctl exists
    if [ -f "/usr/local/bin/1pctl" ]; then
        # Extract configuration from 1pctl
        PANEL_PORT=$(grep "ORIGINAL_PORT=" /usr/local/bin/1pctl | cut -d'=' -f2)
        PANEL_USERNAME=$(grep "ORIGINAL_USERNAME=" /usr/local/bin/1pctl | cut -d'=' -f2)
        PANEL_ENTRANCE=$(grep "ORIGINAL_ENTRANCE=" /usr/local/bin/1pctl | cut -d'=' -f2)
        PANEL_INSTALL_DIR=$(grep "BASE_DIR=" /usr/local/bin/1pctl | cut -d'=' -f2)
    fi

    # Check if 1Panel service is running
    if systemctl is-active --quiet 1panel 2>/dev/null; then
        log "1Panel service is running"
    else
        warning "1Panel service does not appear to be running. You may need to start it manually."
        log "Try: systemctl start 1panel or service 1panel start"
    fi

    # Clean up temporary file
    rm -f "$INSTALL_LOG"

    log "1Panel installation detected:"
    log "  Installation Directory: ${PANEL_INSTALL_DIR}"
    log "  URL: http://${PUBLIC_IP}:${PANEL_PORT}/${PANEL_ENTRANCE}"
    log "  Username: ${PANEL_USERNAME}"
    save_status "1panel_installed"
}

# Configure local firewall
configure_firewall() {
    log "Configuring local firewall..."

    # Ports to open
    PORTS_TO_OPEN=("$NEW_SSH_PORT" "80" "443" "$PANEL_PORT")

    # Check which firewall is installed and active
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        log "Configuring UFW firewall..."

        for PORT in "${PORTS_TO_OPEN[@]}"; do
            log "Opening port $PORT/tcp in UFW"
            ufw allow "$PORT"/tcp
        done

        # Reload UFW to apply changes
        ufw reload
        log "UFW firewall configured successfully"

    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log "Configuring FirewallD..."

        for PORT in "${PORTS_TO_OPEN[@]}"; do
            log "Opening port $PORT/tcp in FirewallD"
            firewall-cmd --permanent --add-port="$PORT"/tcp
        done

        # Reload FirewallD to apply changes
        firewall-cmd --reload
        log "FirewallD configured successfully"

    elif command -v iptables >/dev/null 2>&1; then
        log "Configuring iptables..."

        # Check if iptables-persistent is installed
        IPTABLES_PERSISTENT=false
        if command -v netfilter-persistent >/dev/null 2>&1; then
            IPTABLES_PERSISTENT=true
        fi

        for PORT in "${PORTS_TO_OPEN[@]}"; do
            log "Opening port $PORT/tcp in iptables"
            iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT
        done

        # Save iptables rules if iptables-persistent is installed
        if [ "$IPTABLES_PERSISTENT" = true ]; then
            netfilter-persistent save
            log "iptables rules saved permanently"
        else
            warning "iptables-persistent is not installed. Firewall rules may not persist after reboot."
            warning "To make rules persistent, run: apt-get install iptables-persistent"

            # Save rules to a file that can be loaded manually
            iptables-save > /etc/iptables.rules
            log "iptables rules saved to /etc/iptables.rules"

            # Create a script to load rules at boot
            cat > /etc/network/if-pre-up.d/iptables <<EOF
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.rules
EOF
            chmod +x /etc/network/if-pre-up.d/iptables
            log "Created boot script to load iptables rules"
        fi

        log "iptables configured successfully"
    else
        warning "No supported firewall (ufw, firewalld, iptables) found or active."
        warning "Please manually configure your firewall to open the following ports:"
        for PORT in "${PORTS_TO_OPEN[@]}"; do
            warning "  - $PORT/tcp"
        done
    fi

    log "Local firewall configuration completed"
    log "NOTE: If you are using a cloud provider (like Aliyun), you still need to configure"
    log "      security groups or network ACLs in your cloud provider's console."
    save_status "firewall_configured"
}

# Main execution
main() {
    # Initialize status file with proper permissions
    touch $STATUS_FILE
    chmod 644 $STATUS_FILE
    > $STATUS_FILE

    # Set trap to catch interrupts and failures - with proper exit handling
    trap 'error "Script interrupted. Initiating rollback..."; rollback; exit 0' INT TERM
    trap 'if [ $? -ne 0 ] && [ "$ROLLBACK_DONE" != "true" ]; then error "Script failed. Initiating rollback..."; rollback; fi' EXIT

    log "Starting server initialization..."

    # Get configuration from user
    configure_settings

    # Detect public IP
    detect_public_ip

    # Proceed with installation
    install_docker
    configure_users
    configure_ssh
    setup_uipaas_dirs
    install_nginx
    install_postgres
    install_1panel
    # configure_firewall

    # Get admin user's private key
    UIPAAS_ADMIN_PRIVATE_KEY=$(cat /home/${UIPAAS_ADMIN}/.ssh/id_ed25519)

    # Build PostgreSQL configuration section
    PG_CONFIG_SECTION=""
    if [[ "${INSTALL_POSTGRES}" =~ ^[Yy]$ ]]; then
        PG_CONFIG_SECTION="PostgreSQL Configuration:
Version: ${PG_VERSION}
Database: ${PG_DB}
Username: ${PG_USER}
Password: ${PG_PASSWORD}
Port: ${PG_PORT}
Connection URL: postgresql://${PG_USER}:${PG_PASSWORD}@postgres:${PG_PORT}/${PG_DB}
$(if [[ "${SETUP_BACKUP}" =~ ^[Yy]$ ]]; then echo "Backup: Enabled (Daily at 2:00 AM)"; else echo "Backup: Disabled"; fi)
$(if [[ "${SETUP_BACKUP}" =~ ^[Yy]$ ]] && [ -n "${PG_BACKUP_DIR}" ]; then echo "Backup Location: ${PG_BACKUP_DIR}"; fi)
"
    else
        PG_CONFIG_SECTION="PostgreSQL: Not installed
"
    fi

    # Final configuration summary
    cat <<EOF > server_credentials.txt
=== SERVER CONFIGURATION SUMMARY ===
Root Password: ${ROOT_PASSWORD}
UIPaaS Admin Username: ${UIPAAS_ADMIN}
UIPaaS Admin Password: ${UIPAAS_ADMIN_PASSWORD}

SSH Configuration:
SSH Port: ${NEW_SSH_PORT}
SSH Root Login: $(if [[ "${DISABLE_ROOT_LOGIN}" =~ ^[Yy]$ ]]; then echo "Disabled"; else echo "Enabled"; fi)
SSH Password Auth: $(if [[ "${DISABLE_PASSWORD_AUTH}" =~ ^[Yy]$ ]]; then echo "Disabled"; else echo "Enabled"; fi)

1Panel Configuration:
1Panel URL: http://${PUBLIC_IP}:${PANEL_PORT}/${PANEL_ENTRANCE}
1Panel Username: ${PANEL_USERNAME}
1Panel Password: ${PANEL_PASSWORD}
1Panel Install Directory: ${PANEL_INSTALL_DIR}

${PG_CONFIG_SECTION}

UIPaaS Admin SSH Private Key:
------------------------
${UIPAAS_ADMIN_PRIVATE_KEY}
------------------------

IMPORTANT NEXT STEPS:
1. Save the admin private key shown above (this is required for SSH access)
2. Test SSH access with new port before closing port 22
3. Configure firewall to allow:
   - SSH port (${NEW_SSH_PORT})
   - HTTP (80)
   - HTTPS (443)
   - 1Panel port (${PANEL_PORT})

4. For Aliyun servers:
   - Bind Elastic IP
   - Configure security groups
   - Add all required ports to security groups

5. Add SSH private key to GitHub secrets if needed

- Directory Structure:
  /apps/
  ├── share/
  │   ├── certs/
  │   │   └── <domain>
  │   ├── acme-challenge/
  │   └── html/
  ├── conf/
  │   ├── nginx.conf
  │   ├── default.conf
  │   └── sites-enabled/
  ├── backups/
  │   └── postgres/$(if [[ "${INSTALL_POSTGRES}" =~ ^[Yy]$ ]] && [[ "${SETUP_BACKUP:-}" =~ ^[Yy]$ ]]; then echo " (created when backups enabled)"; fi)
  └── uipaas/
      └── .env$(if [[ "${INSTALL_POSTGRES}" =~ ^[Yy]$ ]]; then echo " (contains PostgreSQL connection info)"; fi)
- Symlink: /home/${UIPAAS_ADMIN}/uipaas -> /apps/uipaas

To test SSH access:
ssh -p ${NEW_SSH_PORT} ${UIPAAS_ADMIN}@${PUBLIC_IP}

SSH SECURITY NOTES:
$(if [[ "${DISABLE_ROOT_LOGIN}" =~ ^[Yy]$ ]]; then echo "- Root login is DISABLED. Use '${UIPAAS_ADMIN}' user and 'sudo' for root access."; else echo "- Root login is enabled"; fi)
$(if [[ "${DISABLE_PASSWORD_AUTH}" =~ ^[Yy]$ ]]; then echo "- Password authentication is DISABLED. You MUST use SSH key authentication."; else echo "- Password authentication is enabled"; fi)

EOF

    chmod 600 server_credentials.txt
    log "Configuration complete! Please check $(pwd)/server_credentials.txt for important information"

    configure_auto_https
}

# New status management functions
save_status() {
    echo "$1" >> $STATUS_FILE
    log "Saved progress: $1"
}

# Improved rollback function to handle missing status file
rollback() {
    export ROLLBACK_DONE="true"
    log "Starting rollback..."

    # Check if status file exists
    if [ ! -f "$STATUS_FILE" ]; then
        log "No installation status found. Nothing to roll back."
        return 0
    fi

    # Process steps in reverse order
    if [ -s "$STATUS_FILE" ]; then
        tac $STATUS_FILE 2>/dev/null | while read step; do
            case $step in
                "firewall_configured")
                    log "Reverting firewall configuration..."
                    # Restore original firewall rules
                    if command -v ufw >/dev/null 2>&1; then
                        ufw --force reset
                    elif command -v firewall-cmd >/dev/null 2>&1; then
                        firewall-cmd --reload
                    elif [ -f "/etc/iptables.rules" ]; then
                        iptables-restore < /etc/iptables.rules
                    fi
                    ;;
                "1panel_installed")
                    log "Removing 1Panel..."
                    if [ -f "/usr/local/bin/1pctl" ]; then
                        /usr/local/bin/1pctl uninstall
                    fi
                    ;;
                "postgres_installed")
                    log "Removing PostgreSQL..."
                    docker rm -f postgres >/dev/null 2>&1 || true
                    docker volume rm postgres_data >/dev/null 2>&1 || true
                    [ -f "/apps/uipaas/.env" ] && rm -f /apps/uipaas/.env
                    ;;
                "directories_created")
                    log "Cleaning up directories..."
                    [ -d "/apps" ] && rm -rf /apps
                    [ -L "/home/${UIPAAS_ADMIN}/uipaas" ] && rm -f /home/${UIPAAS_ADMIN}/uipaas
                    ;;
                "ssh_configured")
                    log "Restoring SSH configuration..."
                    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
                    systemctl restart ssh
                    ;;
                "users_configured")
                    log "Removing admin user..."
                    userdel -r $UIPAAS_ADMIN >/dev/null 2>&1 || true
                    ;;
                "docker_installed")
                    log "Uninstalling Docker..."
                    apt-get purge -y docker-ce docker-ce-cli containerd.io
                    rm -rf /var/lib/docker
                    ;;
                "network_created")
                    log "Removing Docker network..."
                    docker network rm uipaas_network >/dev/null 2>&1 || true
                    ;;
            esac
            log "Rollback step: $step - DONE"
        done
    else
        log "Empty status file. Nothing to roll back."
    fi

    # Cleanup status file
    rm -f $STATUS_FILE
    log "Rollback completed. Status file cleared."
    return 0
}

# Run main function
main