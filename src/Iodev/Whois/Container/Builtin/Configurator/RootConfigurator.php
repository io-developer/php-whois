<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin\Configurator;

use \Iodev\Whois\Container\Builtin\Container;
use \Iodev\Whois\Module\Asn\AsnModule;
use \Iodev\Whois\Module\Tld\TldModule;
use \Iodev\Whois\Whois;

class RootConfigurator implements ConfiguratorInterface
{
    public function configureContainer(Container $container): void
    {
        $container->bindMany([
            Container::ID_COMMON_CLASS_INSTANTIATOR => function (Container $container, string $id) {
                return new $id();
            },

            Whois::class => function(Container $container, string $id) {
                return new Whois(
                    $container,
                    $container->get(TldModule::class),
                    $container->get(AsnModule::class),
                );
            },
        ]);
    }
}
