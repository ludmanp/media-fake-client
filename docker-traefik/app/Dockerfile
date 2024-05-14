FROM composer:latest as composer

FROM php:8.2-fpm

# Set working directory
WORKDIR /app

# Arguments defined in docker-compose.yml
#ARG UID
#ARG GID

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpng-dev \
    libwebp-dev \
    libjpeg62-turbo-dev \
    libfreetype6-dev \
    locales \
    zip \
    libzip-dev \
    jpegoptim optipng pngquant gifsicle \
    vim \
    unzip \
    git \
    curl \
    supervisor

# Clear cache
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Install extensions
RUN docker-php-ext-install zip pdo_mysql exif pcntl bcmath
RUN docker-php-ext-configure gd --with-webp=/usr/include --with-freetype=/usr/include/ --with-jpeg=/usr/include/
RUN docker-php-ext-install gd

# Add xdebug
RUN pecl install xdebug && docker-php-ext-enable xdebug

# Configure Xdebug
RUN echo "xdebug.start_with_request=yes" >> /usr/local/etc/php/conf.d/xdebug.ini \
    && echo "xdebug.mode=debug" >> /usr/local/etc/php/conf.d/xdebug.ini \
    && echo "xdebug.log=/var/xdebug/xdebug.log" >> /usr/local/etc/php/conf.d/xdebug.ini \
    && echo "xdebug.discover_client_host=1" >> /usr/local/etc/php/conf.d/xdebug.ini \
    && mkdir /var/xdebug && chmod -R 777 /var/xdebug


# Updates in php configuratoion
RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini && \
  sed -i "s/memory_limit = .*/memory_limit = 1024M/" /usr/local/etc/php/php.ini && \
  sed -i "s/pm.max_children = .*/pm.max_children = 14/" /usr/local/etc/php-fpm.d/www.conf && \
  sed -i "s/upload_max_filesize = .*/upload_max_filesize = 500M/" /usr/local/etc/php/php.ini && \
  sed -i "s/post_max_size = .*/post_max_size = 500M/" /usr/local/etc/php/php.ini

#Add repository ODBC and Install the Microsoft ODBC driver for SQL Server
RUN curl https://packages.microsoft.com/keys/microsoft.asc | tee /etc/apt/trusted.gpg.d/microsoft.asc \
    && echo "deb [arch=amd64,armhf,arm64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" | tee /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql18 \
    && ACCEPT_EULA=Y apt-get install -y mssql-tools18 \
    && echo 'export PATH="$PATH:/opt/mssql-tools18/bin"' >> ~/.bashrc \
    && apt-get install -y unixodbc-dev \
    && apt-get install -y gcc musl-dev make

# Install the PHP drivers for Microsoft SQL Server

RUN curl -O https://pear.php.net/go-pear.phar

RUN pecl channel-update pecl.php.net \
    && pecl install sqlsrv pdo_sqlsrv \
    && printf "; priority=20\nextension=sqlsrv.so\n" > /usr/local/etc/php/conf.d/sqlsrv.ini \
    && printf "; priority=30\nextension=pdo_sqlsrv.so\n" > /usr/local/etc/php/conf.d/pdo_sqlsrv.ini \
    && pecl clear-cache \
    && rm -rf /tmp/* /var/tmp/*

## nodejs instalation
#ARG NODE_VERSION=18.18.1
#ARG NODE_PACKAGE=node-v$NODE_VERSION-linux-x64
#ARG NODE_HOME=/opt/$NODE_PACKAGE
#
#ENV NODE_PATH $NODE_HOME/lib/node_modules
#ENV PATH $NODE_HOME/bin:$PATH
#
## comes with npm
#RUN curl https://nodejs.org/dist/v$NODE_VERSION/$NODE_PACKAGE.tar.gz | tar -xzC /opt/
#
## Install latest npm version
#RUN npm install -g npm@latest

# Composer
COPY --from=composer /usr/bin/composer /usr/bin/composer

# Expose port 9000 and start php-fpm server
EXPOSE 9000
ENTRYPOINT ["sh", "./docker-traefik/run.sh"]
