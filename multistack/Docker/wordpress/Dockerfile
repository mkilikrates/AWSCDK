FROM wordpress:5.9.2-php7.4-fpm-alpine

COPY uploads.ini /usr/local/etc/php/conf.d/uploads.ini
RUN set -ex; \
	\
	apk add --no-cache --update \
		bash \
		bzip2 \
		less \
		memcached \
		mysql-client \
		oniguruma-dev \
		unzip \
		zip \
		gzip \
		libc6-compat \
	; \
	mkdir -p /usr/src/php/ext; \
	apk add --no-cache --virtual .build-deps \
		$PHPIZE_DEPS \
		curl-dev \
		freetype-dev \
		icu-dev \
		jpeg-dev \
		memcached-dev \
		libmemcached-dev \
		libpng-dev \
		libpq \
		libxml2-dev \
		libzip-dev \
		oniguruma-dev \
	; \
	docker-php-ext-configure gd; \
	docker-php-ext-install -j "$(nproc)" \
		exif \
		gd \
		intl \
		mbstring \
		mysqli \
		opcache \
		pcntl \
		pdo_mysql \
		soap \
		zip \
	; \
	pecl install \
		apcu \
		memcached \
		xhprof \
	; \
	docker-php-ext-enable \
		apcu \
		memcached \
		xhprof \
	 \
	&& chown www-data:www-data /var/www /var/www/html; \
	\
	runDeps="$( \
		scanelf --needed --nobanner --format '%n#p' --recursive /usr/local/lib/php/extensions \
			| tr ',' '\n' \
			| sort -u \
			| awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
	)"; \
	apk add --virtual .wordpress-phpexts-rundeps $runDeps; \
	apk del .build-deps


# https://make.wordpress.org/cli/2018/05/31/gpg-signature-change/
# pub   rsa2048 2018-05-31 [SC]
#	   63AF 7AA1 5067 C056 16FD  DD88 A3A2 E8F2 26F0 BC06
# uid		   [ unknown] WP-CLI Releases <releases@wp-cli.org>
# sub   rsa2048 2018-05-31 [E]

RUN curl https://elasticache-downloads.s3.amazonaws.com/ClusterClient/PHP-7.4/latest-64bit-X86 -o AmazonElastiCacheClusterClient-PHP74-64bit-libmemcached-1.0.18.tar.gz && \
   tar -zxvf AmazonElastiCacheClusterClient-PHP74-64bit-libmemcached-1.0.18.tar.gz && \
   cp amazon-elasticache-cluster-client.so /usr/local/lib/php/extensions/no-debug-non-zts-20190902/ && \
   echo 'extension=amazon-elasticache-cluster-client.so' > /usr/local/etc/php/conf.d/docker-php-ext-memcached.ini

COPY opcache.ini /usr/local/etc/php/conf.d/opcache.ini

WORKDIR /var/www/html

# ENTRYPOINT resets CMD
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["php-fpm"]