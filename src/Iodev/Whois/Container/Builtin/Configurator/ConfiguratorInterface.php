<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin\Configurator;

use \Iodev\Whois\Container\Builtin\Container;

interface ConfiguratorInterface
{
    public function configureContainer(Container $container): void;
}
