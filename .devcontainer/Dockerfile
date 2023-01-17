FROM ubuntu:20.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt update \
    && apt install -y php7.4-cli php7.4-dev php7.4-mbstring php7.4-curl php7.4-intl git zip unzip libicu-dev

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

RUN mkdir -p /xdebug && git clone https://github.com/xdebug/xdebug.git --recursive --branch 3.1.0 /xdebug
RUN cd /xdebug \
    && phpize \
    && ./configure --enable-xdebug \
    && make \
    && make install \
    && echo 'zend_extension=xdebug' > /etc/php/7.4/cli/conf.d/99-xdebug.ini

RUN php -v

CMD ["sleep", "infinity"]