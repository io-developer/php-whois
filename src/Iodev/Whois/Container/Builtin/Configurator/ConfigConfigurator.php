<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin\Configurator;

use \Iodev\Whois\Container\Builtin\Container;
use \Iodev\Whois\Config\{
    ConfigProvider,
    ConfigProviderInterface,
};

class ConfigConfigurator implements ConfiguratorInterface
{
    public function configureContainer(Container $container): void
    {
        $container->bindMany([
            ConfigProviderInterface::class => function(Container $container, string $id) {
                return $container->get(ConfigProvider::class);
            },
        ]);
    }
}
