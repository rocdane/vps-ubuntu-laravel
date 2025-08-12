#!/bin/bash

# Script d'installation pour VPS Ubuntu 24.04 LTS - Laravel 12 Stack
# Version: 1.0
# Auteur: rocdane
# Licence: MIT

# Configuration
DB_ENGINE="postgresql" # Options: postgresql, mysql
APP_USER="devops"
APP_NAME="laravel"
APP_DOMAIN="mydomaine.com"
APP_ROOT="/var/www/html"
PHP_VERSION="8.3"
NODE_VERSION="24"

# Couleurs pour la sortie
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction de journalisation
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Fonction de journalisation d'erreur
error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
    exit 1
}

# Vérification des privilèges root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "Ce script doit être exécuté en tant que root"
    fi
}

# Installation des dépendances de base
install_basic_dependencies() {
    log "Mise à jour des paquets et installation des dépendances de base..."
    apt update && apt upgrade -y || error "Échec de la mise à jour des paquets"
    apt install -y software-properties-common curl apt-transport-https ca-certificates gnupg unzip build-essential || error "Échec de l'installation des dépendances de base"
}

# Configuration de l'utilisateur
setup_user() {
    if id "$APP_USER" &>/dev/null; then
        log "L'utilisateur $APP_USER existe déjà - mise à jour des configurations"
        usermod -aG sudo "$APP_USER" || echo "Avertissement: Impossible d'ajouter l'utilisateur au groupe sudo (peut déjà être membre)"
    else
        log "Création de l'utilisateur $APP_USER..."
        adduser --disabled-password --gecos "" "$APP_USER" || error "Échec critique de la création de l'utilisateur"
        usermod -aG sudo "$APP_USER" || error "Échec critique de l'ajout au groupe sudo"

        # Copie des clés SSH
        if [ -d "/root/.ssh" ]; then
            mkdir -p "/home/$APP_USER/.ssh"
            cp /root/.ssh/authorized_keys "/home/$APP_USER/.ssh/"
            chown -R "$APP_USER:$APP_USER" "/home/$APP_USER/.ssh"
            chmod 700 "/home/$APP_USER/.ssh"
            chmod 600 "/home/$APP_USER/.ssh/authorized_keys"
            log "Clés SSH copiées pour l'utilisateur $APP_USER"
        fi
    fi
}

# Configuration du pare-feu
setup_firewall() {
    log "Configuration du pare-feu UFW..."
    if ! command -v ufw &> /dev/null; then
        apt install -y ufw || error "Échec de l'installation de UFW"
    fi
    
    ufw allow OpenSSH || error "Échec de l'ouverture du port SSH"
    ufw allow 80 || error "Échec de l'ouverture du port HTTP"
    ufw allow 443 || error "Échec de l'ouverture du port HTTPS"
    echo "y" | ufw enable || error "Échec de l'activation de UFW"
}

# Installation de PHP
install_php() {
    log "Installation de PHP $PHP_VERSION et extensions..."
    apt install -y "php$PHP_VERSION" "php$PHP_VERSION-cli" "php$PHP_VERSION-fpm" "php$PHP_VERSION-sqlite3" "php$PHP_VERSION-mbstring" "php$PHP_VERSION-xml" "php$PHP_VERSION-bcmath" "php$PHP_VERSION-curl" "php$PHP_VERSION-zip" "php$PHP_VERSION-gd" "php$PHP_VERSION-redis" "php$PHP_VERSION-opcache" || error "Échec de l'installation de PHP"

    log "Installation du package SQLite3 système..."
    apt install -y sqlite3 libsqlite3-dev || error "Échec de l'installation de SQLite3 système"
        
    # Installation des extensions de base de données en fonction du choix
    if [ "$DB_ENGINE" = "postgresql" ]; then
        apt install -y "php$PHP_VERSION-pgsql" || error "Échec de l'installation de l'extension PostgreSQL pour PHP"
    elif [ "$DB_ENGINE" = "mysql" ]; then
        apt install -y "php$PHP_VERSION-mysql" || error "Échec de l'installation de l'extension MySQL pour PHP"
    fi
    
    # Configuration de PHP-FPM
    sed -i "s/^user = www-data/user = $APP_USER/" "/etc/php/$PHP_VERSION/fpm/pool.d/www.conf"
    sed -i "s/^group = www-data/group = $APP_USER/" "/etc/php/$PHP_VERSION/fpm/pool.d/www.conf"
    
    systemctl restart "php$PHP_VERSION-fpm" || error "Échec du redémarrage de PHP-FPM"
}

# Installation de la base de données
install_database() {
    if [ "$DB_ENGINE" = "postgresql" ]; then
        log "Installation de PostgreSQL..."
        apt install -y postgresql postgresql-contrib || error "Échec de l'installation de PostgreSQL"
        
        log "Configuration de PostgreSQL pour Laravel..."
        # Version améliorée avec gestion d'erreur idempotente
        sudo -u postgres psql -v ON_ERROR_STOP=0 -c "DO \$\$ BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$APP_USER') THEN
                CREATE ROLE $APP_USER WITH LOGIN PASSWORD 'temp_password';
                RAISE NOTICE 'Utilisateur $APP_USER créé avec succès';
            ELSE
                ALTER ROLE $APP_USER WITH PASSWORD 'temp_password';
                RAISE NOTICE 'Utilisateur $APP_USER existe déjà, mot de passe mis à jour';
            END IF;
        END \$\$;" || echo "Avertissement: Gestion de l'utilisateur PostgreSQL (peut déjà exister)"
        
        sudo -u postgres psql -v ON_ERROR_STOP=0 -c "CREATE DATABASE $APP_NAME WITH OWNER $APP_USER ENCODING 'UTF8' LC_COLLATE 'fr_FR.utf8' LC_CTYPE 'fr_FR.utf8';" || echo "Avertissement: La base de données existe peut-être déjà"
        
    elif [ "$DB_ENGINE" = "mysql" ]; then
        log "Installation de MySQL..."
        apt install -y mysql-server || error "Échec de l'installation de MySQL"
        
        log "Configuration de MySQL pour Laravel..."
        # Version idempotente pour MySQL
        mysql -e "CREATE DATABASE IF NOT EXISTS $APP_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" || echo "Avertissement: La base de données existe peut-être déjà"
        mysql -e "CREATE USER IF NOT EXISTS '$APP_USER'@'localhost' IDENTIFIED BY 'temp_password';" || echo "Avertissement: L'utilisateur existe peut-être déjà"
        mysql -e "GRANT ALL PRIVILEGES ON $APP_NAME.* TO '$APP_USER'@'localhost';" || echo "Avertissement: Problème d'attribution des privilèges"
        mysql -e "FLUSH PRIVILEGES;" || echo "Avertissement: Problème de rechargement des privilèges"
    fi
}

# Installation de Node.js
install_nodejs() {
    log "Installation de Node.js $NODE_VERSION..."
    curl -fsSL "https://deb.nodesource.com/setup_$NODE_VERSION.x" | bash - || error "Échec de l'ajout du dépôt Node.js"
    apt install -y nodejs || error "Échec de l'installation de Node.js"
}

# Installation de Nginx
install_nginx() {
    log "Installation de Nginx..."
    apt install -y nginx || error "Échec de l'installation de Nginx"
    
    log "Configuration de Nginx pour Laravel..."
    cat > "/etc/nginx/sites-available/$APP_NAME" <<EOF
server {
    listen 80;
    server_name $APP_DOMAIN;
    root $APP_ROOT/public;

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";

    index index.php;

    charset utf-8;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }

    error_page 404 /index.php;

    location ~ \.php\$ {
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }
}
EOF
    
    ln -s "/etc/nginx/sites-available/$APP_NAME" "/etc/nginx/sites-enabled/" || error "Échec de l'activation du site Nginx"
    rm -f /etc/nginx/sites-enabled/default
    
    nginx -t || error "Configuration Nginx invalide"
    systemctl restart nginx || error "Échec du redémarrage de Nginx"
}

# Installation de Supervisor
install_supervisor() {
    log "Installation de Supervisor..."
    apt install -y supervisor || error "Échec de l'installation de Supervisor"
    
    log "Configuration de Supervisor pour les queues Laravel..."
    cat > "/etc/supervisor/conf.d/laravel-worker.conf" <<EOF
[program:laravel-worker]
process_name=%(program_name)s_%(process_num)02d
command=php $APP_ROOT/artisan queue:work --sleep=3 --tries=3
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
user=$APP_USER
numprocs=2
redirect_stderr=true
stdout_logfile=$APP_ROOT/storage/logs/worker.log
stopwaitsecs=3600
EOF
    
    supervisorctl reread || error "Échec de la relecture de la configuration Supervisor"
    supervisorctl update || error "Échec de la mise à jour de Supervisor"
    supervisorctl start laravel-worker:* || error "Échec du démarrage des workers Laravel"
}

# Configuration de l'environnement Laravel
setup_laravel_environment() {
    log "Configuration de l'environnement Laravel..."
    
    mkdir -p "$APP_ROOT" || error "Échec de la création du répertoire de l'application"
    chown -R "$APP_USER:$APP_USER" "$APP_ROOT" || error "Échec du changement de propriétaire du répertoire de l'application"
    
    # Configuration des permissions
    mkdir -p "$APP_ROOT/storage" "$APP_ROOT/bootstrap/cache" || error "Échec de la création des répertoires storage/cache"
    chmod -R 775 "$APP_ROOT/storage" "$APP_ROOT/bootstrap/cache" || error "Échec de la configuration des permissions"
    chown -R "$APP_USER:www-data" "$APP_ROOT/storage" "$APP_ROOT/bootstrap/cache" || error "Échec du changement de propriétaire des répertoires storage/cache"
    
    # Configuration du fichier .env
    touch "$APP_ROOT/.env" || error "Échec de la création du fichier .env"
    chown "$APP_USER:$APP_USER" "$APP_ROOT/.env" || error "Échec du changement de propriétaire du fichier .env"
    chmod 600 "$APP_ROOT/.env" || error "Échec de la configuration des permissions du fichier .env"
}

# Installation finale et nettoyage
finalize_installation() {
    log "Nettoyage et finalisation de l'installation..."
    apt autoremove -y
    apt clean
    
    log "Installation terminée avec succès!"
    log "Récapitulatif de la configuration:"
    log " - Utilisateur: $APP_USER"
    log " - Répertoire de l'application: $APP_ROOT"
    log " - PHP version: $PHP_VERSION"
    log " - Node.js version: $NODE_VERSION"
    log " - Base de données: $DB_ENGINE"
    log " - Nom de la base de données: $APP_NAME"
    log " - Domaine: $APP_DOMAIN"
    
    echo -e "${YELLOW}IMPORTANT:${NC}"
    echo -e "${YELLOW}1. Configurez votre fichier .env avec les informations de connexion à la base de données${NC}"
    echo -e "${YELLOW}2. Changez le mot de passe par défaut de la base de données${NC}"
}

# Fonction principale
main() {
    check_root
    install_basic_dependencies
    setup_user
    setup_firewall
    install_php
    install_database
    install_nodejs
    install_nginx
    install_supervisor
    setup_laravel_environment
    finalize_installation
}

# Exécution du script
main