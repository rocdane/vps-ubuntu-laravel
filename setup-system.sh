#!/bin/bash

#==============================================================================
# Script de Configuration VPS pour Laravel 12 / PHP 8.3 / Node.js 24
# Version: 1.0
# Auteur: Ingénieur Système
# Description: Configuration complète et optimisée d'un serveur VPS
#==============================================================================

set -euo pipefail  # Arrêt en cas d'erreur

# Variables de configuration
readonly PHP_VERSION="8.3"
readonly NODE_VERSION="24"
readonly LARAVEL_VERSION="12"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/vps-setup.log"
readonly DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Variables SSL (à personnaliser selon votre configuration)
SSL_CERT_PATH="${SSL_CERT_PATH:-/etc/ssl/certs}"
SSL_KEY_PATH="${SSL_KEY_PATH:-/etc/ssl/private}"
SSL_CERT_NAME="${SSL_CERT_NAME:-server.crt}"
SSL_KEY_NAME="${SSL_KEY_NAME:-server.key}"

# Couleurs pour l'affichage
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

#==============================================================================
# FONCTIONS UTILITAIRES
#==============================================================================

log() {
    echo -e "${GREEN}[${DATE}]${NC} $1" | tee -a "${LOG_FILE}"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_FILE}"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${LOG_FILE}"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "${LOG_FILE}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en tant que root"
    fi
}

create_user() {
    local username="$1"
    if ! id "$username" &>/dev/null; then
        log "Création de l'utilisateur $username"
        useradd -m -s /bin/bash "$username"
        usermod -aG sudo "$username"
        mkdir -p "/home/$username/.ssh"
        chmod 700 "/home/$username/.ssh"
        chown "$username:$username" "/home/$username/.ssh"
    else
        info "L'utilisateur $username existe déjà"
    fi
}

#==============================================================================
# MISE À JOUR SYSTÈME
#==============================================================================

system_update() {
    log "Mise à jour du système..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get autoremove -y -qq
    
    # Installation des outils de base
    apt-get install -y -qq \
        curl \
        wget \
        git \
        unzip \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg2 \
        lsb-release \
        htop \
        nano \
        vim \
        tree \
        zip \
        fail2ban \
        ufw \
        supervisor \
        redis-server \
        certbot
    
    log "Système mis à jour avec succès"
}

#==============================================================================
# CONFIGURATION SÉCURITÉ
#==============================================================================

configure_security() {
    log "Configuration de la sécurité..."
    
    # Configuration UFW
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    
    # Configuration Fail2Ban
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log "Sécurité configurée"
}

#==============================================================================
# INSTALLATION NGINX
#==============================================================================

install_nginx() {
    log "Installation et configuration de Nginx..."
    
    apt-get install -y -qq nginx
    
    # Configuration globale optimisée
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 2048;
    use epoll;
    multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 100M;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    # Logging Settings
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Gzip Settings
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Suppression du site par défaut
    rm -f /etc/nginx/sites-enabled/default
    
    # Test et démarrage de Nginx
    nginx -t
    systemctl enable nginx
    systemctl restart nginx
    
    log "Nginx installé et configuré"
}

#==============================================================================
# INSTALLATION PHP 8.3
#==============================================================================

install_php() {
    log "Installation de PHP ${PHP_VERSION}..."
    
    # Ajout du repository PHP
    add-apt-repository -y ppa:ondrej/php
    apt-get update -qq
    
    # Installation PHP et extensions
    apt-get install -y -qq \
        php${PHP_VERSION}-fpm \
        php${PHP_VERSION}-cli \
        php${PHP_VERSION}-common \
        php${PHP_VERSION}-mysql \
        php${PHP_VERSION}-pgsql \
        php${PHP_VERSION}-sqlite3 \
        php${PHP_VERSION}-redis \
        php${PHP_VERSION}-xml \
        php${PHP_VERSION}-mbstring \
        php${PHP_VERSION}-curl \
        php${PHP_VERSION}-gd \
        php${PHP_VERSION}-imagick \
        php${PHP_VERSION}-zip \
        php${PHP_VERSION}-bcmath \
        php${PHP_VERSION}-intl \
        php${PHP_VERSION}-readline \
        php${PHP_VERSION}-dev \
        php${PHP_VERSION}-xdebug
    
    # Configuration PHP optimisée
    cat > /etc/php/${PHP_VERSION}/fpm/conf.d/99-laravel.ini << 'EOF'
; Optimisations Laravel
memory_limit = 512M
upload_max_filesize = 100M
post_max_size = 100M
max_execution_time = 300
max_input_vars = 3000
date.timezone = Europe/Paris

; OPcache
opcache.enable = 1
opcache.enable_cli = 1
opcache.memory_consumption = 256
opcache.interned_strings_buffer = 16
opcache.max_accelerated_files = 10000
opcache.revalidate_freq = 2
opcache.fast_shutdown = 1

; Session
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
EOF

    # Configuration FPM
    sed -i 's/;listen.owner = www-data/listen.owner = www-data/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
    sed -i 's/;listen.group = www-data/listen.group = www-data/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
    sed -i 's/;listen.mode = 0660/listen.mode = 0660/' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
    
    systemctl enable php${PHP_VERSION}-fpm
    systemctl restart php${PHP_VERSION}-fpm
    
    log "PHP ${PHP_VERSION} installé et configuré"
}

#==============================================================================
# INSTALLATION COMPOSER
#==============================================================================

install_composer() {
    log "Installation de Composer..."
    
    cd /tmp
    curl -sS https://getcomposer.org/installer -o composer-setup.php
    php composer-setup.php --install-dir=/usr/local/bin --filename=composer
    rm composer-setup.php
    
    # Vérification
    composer --version
    
    log "Composer installé"
}

#==============================================================================
# INSTALLATION NODE.JS
#==============================================================================

install_nodejs() {
    log "Installation de Node.js ${NODE_VERSION}..."
    
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
    apt-get install -y -qq nodejs
    
    # Mise à jour npm
    npm install -g npm@latest
    
    # Installation des outils globaux
    npm install -g yarn pm2
    
    # Vérifications
    node --version
    npm --version
    yarn --version
    
    log "Node.js ${NODE_VERSION} installé"
}

#==============================================================================
# INSTALLATION MYSQL
#==============================================================================

install_mysql() {
    log "Installation de MySQL..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq mysql-server
    
    # Sécurisation MySQL
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD:-TempPassword123!}';"
    mysql -e "DELETE FROM mysql.user WHERE User='';"
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    mysql -e "DROP DATABASE IF EXISTS test;"
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Configuration optimisée
    cat >> /etc/mysql/mysql.conf.d/mysqld.cnf << 'EOF'

# Optimisations Laravel
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
query_cache_type = 1
query_cache_size = 32M
max_connections = 200
EOF

    systemctl enable mysql
    systemctl restart mysql
    
    log "MySQL installé et configuré"
}

#==============================================================================
# CONFIGURATION REDIS
#==============================================================================

configure_redis() {
    log "Configuration de Redis..."
    
    # Configuration sécurisée
    sed -i 's/# maxmemory <bytes>/maxmemory 256mb/' /etc/redis/redis.conf
    sed -i 's/# maxmemory-policy noeviction/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
    
    systemctl enable redis-server
    systemctl restart redis-server
    
    log "Redis configuré"
}

#==============================================================================
# CONFIGURATION SUPERVISOR
#==============================================================================

configure_supervisor() {
    log "Configuration de Supervisor..."
    
    # Template pour les workers Laravel
    mkdir -p /etc/supervisor/conf.d
    
    cat > /etc/supervisor/conf.d/laravel-template.conf << 'EOF'
[program:laravel-queue-worker]
process_name=%(program_name)s_%(process_num)02d
command=php /var/www/html/artisan queue:work --sleep=3 --tries=3 --max-time=3600
directory=/var/www/html
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
user=www-data
numprocs=2
redirect_stderr=true
stdout_logfile=/var/log/supervisor/laravel-queue-worker.log
stopwaitsecs=3600
EOF

    systemctl enable supervisor
    systemctl restart supervisor
    
    log "Supervisor configuré"
}

#==============================================================================
# DÉTECTION ET CONFIGURATION SSL
#==============================================================================

detect_ssl_config() {
    local domain="$1"
    local ssl_config=""
    
    # Vérification des certificats Let's Encrypt
    if [[ -f "/etc/letsencrypt/live/$domain/fullchain.pem" && -f "/etc/letsencrypt/live/$domain/privkey.pem" ]]; then
        ssl_config="letsencrypt"
        SSL_CERT_PATH="/etc/letsencrypt/live/$domain/fullchain.pem"
        SSL_KEY_PATH="/etc/letsencrypt/live/$domain/privkey.pem"
        log "Certificats Let's Encrypt détectés pour $domain"
        
    # Vérification des certificats personnalisés
    elif [[ -f "$SSL_CERT_PATH/$SSL_CERT_NAME" && -f "$SSL_KEY_PATH/$SSL_KEY_NAME" ]]; then
        ssl_config="custom"
        log "Certificats personnalisés détectés"
        
    # Vérification des certificats dans d'autres emplacements communs
    elif [[ -f "/etc/ssl/certs/$domain.crt" && -f "/etc/ssl/private/$domain.key" ]]; then
        ssl_config="standard"
        SSL_CERT_PATH="/etc/ssl/certs/$domain.crt"
        SSL_KEY_PATH="/etc/ssl/private/$domain.key"
        log "Certificats standard détectés pour $domain"
        
    else
        warning "Aucun certificat SSL détecté - configuration HTTP uniquement"
        ssl_config="none"
    fi
    
    echo "$ssl_config"
}

#==============================================================================
# CRÉATION DU TEMPLATE NGINX POUR LARAVEL
#==============================================================================

create_nginx_template() {
    log "Création du template Nginx pour Laravel..."
    
    mkdir -p /etc/nginx/templates
    
    # Template avec SSL
    cat > /etc/nginx/templates/laravel-ssl.conf << 'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_NAME;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name DOMAIN_NAME;
    
    root /var/www/PROJECT_NAME/public;
    index index.php index.html;
    
    # SSL Configuration
    ssl_certificate SSL_CERT_PATH;
    ssl_certificate_key SSL_KEY_PATH;
    
    ssl_session_cache shared:le_nginx_SSL:10m;
    ssl_session_timeout 1440m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Laravel configuration
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }
    
    error_page 404 /index.php;
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
        
        # Optimisations
        fastcgi_buffers 16 16k;
        fastcgi_buffer_size 32k;
        fastcgi_read_timeout 300;
    }
    
    location ~ /\.(?!well-known).* {
        deny all;
    }
    
    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # Gzip
    gzip on;
    gzip_types text/css application/javascript text/javascript application/json;
}
EOF

    # Template sans SSL (HTTP uniquement)
    cat > /etc/nginx/templates/laravel-http.conf << 'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_NAME;
    
    root /var/www/PROJECT_NAME/public;
    index index.php index.html;
    
    # Security headers (adaptées pour HTTP)
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    
    # Laravel configuration
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }
    
    error_page 404 /index.php;
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
        
        # Optimisations
        fastcgi_buffers 16 16k;
        fastcgi_buffer_size 32k;
        fastcgi_read_timeout 300;
    }
    
    location ~ /\.(?!well-known).* {
        deny all;
    }
    
    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # Gzip
    gzip on;
    gzip_types text/css application/javascript text/javascript application/json;
}
EOF

    log "Template Nginx créé"
}

#==============================================================================
# SCRIPT D'AIDE POUR NOUVEAU PROJET
#==============================================================================

create_project_helper() {
    log "Création du script d'aide pour nouveaux projets..."
    
    cat > /usr/local/bin/laravel-new-project << 'EOF'
#!/bin/bash

# Script d'aide pour créer un nouveau projet Laravel
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <project_name> <domain_name> [mysql_password] [ssl_cert_path] [ssl_key_path]"
    echo "Exemple: $0 monapp example.com"
    echo "Avec SSL: $0 monapp example.com '' /path/to/cert.pem /path/to/key.pem"
    exit 1
fi

PROJECT_NAME="$1"
DOMAIN_NAME="$2"
MYSQL_PASS="${3:-$(openssl rand -base64 32)}"
CUSTOM_CERT="${4:-}"
CUSTOM_KEY="${5:-}"

echo "=== Création du projet Laravel: $PROJECT_NAME ==="

# Détection SSL
SSL_CONFIG="none"
SSL_CERT_PATH=""
SSL_KEY_PATH=""
TEMPLATE_FILE="laravel-http.conf"

if [[ -n "$CUSTOM_CERT" && -n "$CUSTOM_KEY" ]]; then
    if [[ -f "$CUSTOM_CERT" && -f "$CUSTOM_KEY" ]]; then
        SSL_CONFIG="custom"
        SSL_CERT_PATH="$CUSTOM_CERT"
        SSL_KEY_PATH="$CUSTOM_KEY"
        TEMPLATE_FILE="laravel-ssl.conf"
        echo "✓ Certificats SSL personnalisés détectés"
    else
        echo "⚠ Certificats SSL personnalisés introuvables, configuration HTTP"
    fi
elif [[ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]]; then
    SSL_CONFIG="letsencrypt"
    SSL_CERT_PATH="/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem"
    SSL_KEY_PATH="/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem"
    TEMPLATE_FILE="laravel-ssl.conf"
    echo "✓ Certificats Let's Encrypt détectés"
elif [[ -f "/etc/ssl/certs/$DOMAIN_NAME.crt" ]]; then
    SSL_CONFIG="standard"
    SSL_CERT_PATH="/etc/ssl/certs/$DOMAIN_NAME.crt"
    SSL_KEY_PATH="/etc/ssl/private/$DOMAIN_NAME.key"
    TEMPLATE_FILE="laravel-ssl.conf"
    echo "✓ Certificats SSL standard détectés"
else
    echo "⚠ Aucun certificat SSL détecté - Configuration HTTP uniquement"
fi

# Création du projet
cd /var/www
composer create-project laravel/laravel="^11.0" "$PROJECT_NAME"
cd "$PROJECT_NAME"

# Permissions
chown -R www-data:www-data /var/www/"$PROJECT_NAME"
chmod -R 755 /var/www/"$PROJECT_NAME"
chmod -R 775 /var/www/"$PROJECT_NAME"/storage
chmod -R 775 /var/www/"$PROJECT_NAME"/bootstrap/cache

# Base de données
mysql -u root -p -e "CREATE DATABASE ${PROJECT_NAME}_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p -e "CREATE USER '${PROJECT_NAME}_user'@'localhost' IDENTIFIED BY '$MYSQL_PASS';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON ${PROJECT_NAME}_db.* TO '${PROJECT_NAME}_user'@'localhost';"
mysql -u root -p -e "FLUSH PRIVILEGES;"

# Configuration Nginx
if [[ "$SSL_CONFIG" != "none" ]]; then
    sed "s|DOMAIN_NAME|$DOMAIN_NAME|g; s|PROJECT_NAME|$PROJECT_NAME|g; s|SSL_CERT_PATH|$SSL_CERT_PATH|g; s|SSL_KEY_PATH|$SSL_KEY_PATH|g" \
        "/etc/nginx/templates/$TEMPLATE_FILE" > "/etc/nginx/sites-available/$PROJECT_NAME"
else
    sed "s|DOMAIN_NAME|$DOMAIN_NAME|g; s|PROJECT_NAME|$PROJECT_NAME|g" \
        "/etc/nginx/templates/$TEMPLATE_FILE" > "/etc/nginx/sites-available/$PROJECT_NAME"
fi

ln -sf "/etc/nginx/sites-available/$PROJECT_NAME" "/etc/nginx/sites-enabled/$PROJECT_NAME"

# Test et reload Nginx
nginx -t && systemctl reload nginx

echo "=== Projet créé avec succès ==="
echo "Domaine: $DOMAIN_NAME"
echo "Chemin: /var/www/$PROJECT_NAME"
echo "Base de données: ${PROJECT_NAME}_db"
echo "Utilisateur DB: ${PROJECT_NAME}_user"
echo "Mot de passe DB: $MYSQL_PASS"
echo "SSL: $SSL_CONFIG"
if [[ "$SSL_CONFIG" != "none" ]]; then
    echo "Certificat: $SSL_CERT_PATH"
    echo "Clé privée: $SSL_KEY_PATH"
fi
echo ""
echo "N'oubliez pas de configurer le fichier .env !"
EOF

    # Ajout d'un script d'aide pour la gestion SSL
    cat > /usr/local/bin/laravel-ssl-setup << 'EOF'
#!/bin/bash

# Script pour configurer SSL sur un projet existant
set -euo pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $0 <project_name> <domain_name> <cert_path> <key_path>"
    echo "Exemple: $0 monapp example.com /path/to/cert.pem /path/to/key.pem"
    exit 1
fi

PROJECT_NAME="$1"
DOMAIN_NAME="$2"
CERT_PATH="$3"
KEY_PATH="$4"

if [[ ! -f "$CERT_PATH" || ! -f "$KEY_PATH" ]]; then
    echo "Erreur: Certificat ou clé privée introuvable"
    exit 1
fi

echo "=== Configuration SSL pour: $PROJECT_NAME ==="

# Reconfiguration Nginx avec SSL
sed "s|DOMAIN_NAME|$DOMAIN_NAME|g; s|PROJECT_NAME|$PROJECT_NAME|g; s|SSL_CERT_PATH|$CERT_PATH|g; s|SSL_KEY_PATH|$KEY_PATH|g" \
    /etc/nginx/templates/laravel-ssl.conf > "/etc/nginx/sites-available/$PROJECT_NAME"

# Test et reload
nginx -t && systemctl reload nginx

echo "✓ SSL configuré avec succès pour $DOMAIN_NAME"
EOF

    chmod +x /usr/local/bin/laravel-ssl-setup
    
    log "Scripts d'aide créés: laravel-new-project, laravel-ssl-setup"
}

#==============================================================================
# OPTIMISATIONS SYSTÈME
#==============================================================================

system_optimizations() {
    log "Application des optimisations système..."
    
    # Optimisations mémoire et réseau
    cat >> /etc/sysctl.conf << 'EOF'

# Optimisations pour serveur web
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_slow_start_after_idle = 0
vm.swappiness = 10
EOF

    sysctl -p
    
    # Logrotate pour les logs Laravel
    cat > /etc/logrotate.d/laravel << 'EOF'
/var/www/*/storage/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
}
EOF

    log "Optimisations appliquées"
}

#==============================================================================
# FONCTION PRINCIPALE
#==============================================================================

main() {
    local username="${1:-deploy}"
    
    log "=== Début de la configuration VPS pour Laravel ==="
    log "PHP: ${PHP_VERSION} | Node.js: ${NODE_VERSION} | Laravel: ${LARAVEL_VERSION}"
    
    check_root
    
    # Exécution des étapes
    system_update
    configure_security
    create_user "$username"
    install_nginx
    install_php
    install_composer
    install_nodejs
    install_mysql
    configure_redis
    configure_supervisor
    create_nginx_template
    create_project_helper
    system_optimizations
    
    log "=== Configuration terminée avec succès ==="
    
    # Affichage des informations importantes
    echo -e "\n${GREEN}================================${NC}"
    echo -e "${GREEN}  CONFIGURATION TERMINÉE${NC}"
    echo -e "${GREEN}================================${NC}"
    echo -e "${YELLOW}Services installés:${NC}"
    echo "  ✓ Nginx $(nginx -v 2>&1 | cut -d' ' -f3)"
    echo "  ✓ PHP $(php --version | head -n1 | cut -d' ' -f2)"
    echo "  ✓ MySQL $(mysql --version | cut -d' ' -f6 | cut -d',' -f1)"
    echo "  ✓ Redis $(redis-server --version | cut -d' ' -f3 | cut -d'=' -f2)"
    echo "  ✓ Node.js $(node --version)"
    echo "  ✓ Composer $(composer --version | cut -d' ' -f3)"
    echo ""
    echo -e "${YELLOW}Commandes utiles:${NC}"
    echo "  • Nouveau projet: laravel-new-project <nom> <domaine> [cert] [key]"
    echo "  • Config SSL: laravel-ssl-setup <projet> <domaine> <cert> <key>"
    echo "  • Logs système: tail -f /var/log/vps-setup.log"
    echo "  • Status services: systemctl status nginx php8.3-fpm mysql"
    echo ""
    echo -e "${YELLOW}Prochaines étapes:${NC}"
    echo "  1. Configurez vos clés SSH pour l'utilisateur '$username'"
    echo "  2. Changez le mot de passe root MySQL"
    echo "  3. Créez votre premier projet Laravel"
    echo ""
    echo -e "${RED}Important:${NC} Mot de passe MySQL root temporaire dans les logs"
}

# Exécution du script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi