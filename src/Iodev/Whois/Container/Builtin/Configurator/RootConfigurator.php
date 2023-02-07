<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin\Configurator;

use \InvalidArgumentException;
use \Iodev\Whois\Container\Builtin\Container;
use \Iodev\Whois\Module\Asn\AsnModule;
use \Iodev\Whois\Module\Tld\TldModule;
use \Iodev\Whois\Whois;

class RootConfigurator implements ConfiguratorInterface
{
    public function configureContainer(Container $container): void
    {
        $container->bindMany([
            '@default' => function (Container $container, string $id) {
                if (class_exists($id)) {
                    return new $id();
                }
                throw new InvalidArgumentException("Class '$id' not found");
            },

            Whois::class => function(Container $container) {
                return new Whois(
                    $container,
                    $container->get(TldModule::class),
                    $container->get(AsnModule::class),
                );
            },
        ]);
    }
}
