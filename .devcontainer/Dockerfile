FROM ubuntu:22.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt update \
    && apt install -y git curl \
        php8.1-cli \
        php8.1-mbstring \
        php8.1-curl \
        php8.1-intl \
        php8.1-dom \
        php8.1-xml \
        php8.1-xdebug

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

RUN php -v