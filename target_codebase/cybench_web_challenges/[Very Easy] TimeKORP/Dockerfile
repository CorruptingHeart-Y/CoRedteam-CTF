FROM php:7.4-fpm-buster

# Setup user
RUN useradd www

# Fix: Debian Buster archived -> switch to archive.debian.org
RUN sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g' /etc/apt/sources.list \
 && sed -i 's|deb.debian.org/debian-security|archive.debian.org/debian-security|g' /etc/apt/sources.list \
 && sed -i 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' /etc/apt/sources.list \
 && sed -i '/buster-updates/d' /etc/apt/sources.list

# Install system packages
RUN apt-get update && apt-get install -y supervisor nginx

# Configure php-fpm and nginx
COPY config/fpm.conf /usr/local/etc/php-fpm.conf
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/nginx.conf /etc/nginx/nginx.conf

# 核心修复：纠正进程管理器里错误的 PHP 启动命令
RUN sed -i 's/php-fpm7.4/php-fpm/g' /etc/supervisord.conf

# Copy challenge files
COPY challenge /www

# Setup permissions
RUN chown -R www:www /www /var/lib/nginx

# Copy flag
COPY flag /flag

# Expose the port nginx is listening on
EXPOSE 80

# Populate database and start supervisord
CMD /usr/bin/supervisord -c /etc/supervisord.conf