#!/usr/bin/env sh

composer update

php vendor/bin/phpunit --bootstrap tests/bootstrap.php tests $@
