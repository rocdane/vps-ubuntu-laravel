# Guide Technique pour Configurer un VPS Ubuntu 24.04 LTS pour Laravel 12

Ce guide fournit des instructions détaillées pour configurer un serveur VPS IONOS avec une stack optimisée pour Laravel 12.

## Table des Matières

1. [Prérequis](#prérequis)
2. [Configuration Initiale](#configuration-initiale-du-serveur)
3. [Installation des Composants](#installation-des-composants)
4. [Configuration des Services](#configuration-des-services)
5. [Optimisation Laravel](#optimisation-laravel)
6. [Script d'Installation](#script-dinstallation-automatisé)

## [Prérequis](prérequis)

Avant de commencer, assurez-vous d'avoir :

- Un VPS IONOS avec Ubuntu 24.04 LTS fraîchement installé
- Un nom de domaine valide pointant vers l'IP de votre VPS
- Un certificat SSL valide pour votre domaine
- Un accès SSH avec privilèges root
- Au moins 1 Go de RAM (2 Go recommandé pour la production)

## [Configuration Initiale du Serveur](configuration-initiale-du-serveur)

### 1. Connexion SSH sécurisée

```bash
ssh root@votre_ip_serveur
```

### 2. Mise à jour du système

```bash
apt update && apt upgrade -y
apt install -y software-properties-common curl apt-transport-https ca-certificates gnupg
```

### 3. Création d'un utilisateur dédié

```bash
adduser deployer
usermod -aG sudo deployer
rsync --archive --chown=deployer:deployer ~/.ssh /home/deployer
```

### 4. Configuration du par-feu

```bash
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
```

## [Installation des composants](installation-des-composants)

### 5. PHP 8.3 avec extentions

```bash
add-apt-repository -y ppa:ondrej/php
apt update
apt install -y php8.3 php8.3-fpm php8.3-{cli,mbstring,xml,bcmath,curl,zip,gd,pgsql,mysql,sqlite3,redis,opcache}
```

### 6. Node.js 24

```bash
curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
apt install -y nodejs
```

### 7. Autres dépendances

```bash
apt install -y git unzip nginx supervisor
```

### 8. Base de données (au choix)

```bash
apt install -y postgresql postgresql-contrib

apt install -y mysql-server
```

## [Configuration des services](configuration-des-services)

### Nginx

- Configuration du virtual host pour Laravel
- Optimisation des paramètres de performance
- Configuration SSL (si certificat disponible)

### PostgreSQL/MySQL

- Création de l'utilisateur et de la base de données
- Configuration des accès sécurisés

### Supervisor

- Configuration pour les queues Laravel
- Gestion des processus workers

### PHP-FPM

- Optimisation des paramètres pour la production
- Configuration des pools

## [Optimisation Laravel](optimisation-laravel)

### Permissions des dossiers

```bash
chown -R deployer:www-data /var/www/html/storage
chown -R deployer:www-data /var/www/html/bootstrap/cache
chmod -R 775 /var/www/html/storage
chmod -R 775 /var/www/html/bootstrap/cache
```

### Configuration .env

- Protection du fichier .env
- Configuration des variables sensibles

### Optimisation des performances

```bash
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

## [Script d'installation automatisée](script-dinstallation-automatisé)

Un script complet est disponible avec les fonctionnalités suivantes :

- Installation en une seule commande
- Gestion des erreurs détaillée
- Journalisation des opérations
- Configuration automatique de tous les composants
- Options personnalisables

```bash
git clone https://github.com/rocdane/vps-ubuntu-laravel
cd vps-ubuntu-laravel
chmod +x config.sh
sudo ./config.sh
```

## Recommandations Post-Installation

1. Configurer des sauvegardes automatiques
2. Mettre en place la surveillance du serveur
3. Configurer Fail2Ban pour la sécurité
4. Mettre à jour régulièrement les paquets

## Support

Pour toute question ou problème, consultez la documentation officielle de :

- [Laravel](https://laravel.com/docs)
- [Ubuntu Server](https://laravel.com/docs)
