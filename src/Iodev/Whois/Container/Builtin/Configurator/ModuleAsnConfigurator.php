<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin\Configurator;

use \Iodev\Whois\Container\Builtin\Container;
use \Iodev\Whois\Module\Asn\{
    AsnModule,
    AsnParser,
    AsnServerProvider,
    AsnServerProviderInterface,
};
use \Iodev\Whois\Transport\{
    Loader\LoaderInterface,
};
use \Iodev\Whois\Tool\{
    ParserTool,
};

class ModuleAsnConfigurator implements ConfiguratorInterface
{
    public function configureContainer(Container $container): void
    {
        $container->bindMany([
            AsnModule::class => function(Container $container, string $id) {
                /** @var AsnServerProviderInterface */
                $provider = $container->get(AsnServerProviderInterface::class);
                $servers = $provider->getList();

                $instance = new AsnModule(
                    $container->get(LoaderInterface::class),
                );
                $instance->setServers($servers);
                return $instance;
            },

            AsnServerProviderInterface::class => function(Container $container, string $id) {
                return $container->get(AsnServerProvider::class);
            },

            AsnServerProvider::class => function(Container $container, string $id) {
                return new AsnServerProvider(
                    $container,
                );
            },

            AsnParser::class => function(Container $container, string $id) {
                return new AsnParser(
                    $container->get(ParserTool::class),
                );
            },
        ]);
    }
}
