#!/bin/bash

chown -R www-data:www-data /app/storage/
chown -R www-data:www-data /app/bootstrap/
chmod 700 -R /app/storage/
chmod 700 -R /app/bootstrap/

/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisordautostart.conf &
php-fpm
