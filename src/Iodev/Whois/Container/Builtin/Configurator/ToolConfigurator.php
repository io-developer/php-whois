<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin\Configurator;

use \Iodev\Whois\Container\Builtin\Container;
use \Iodev\Whois\Tool\{
    DomainTool,
    PunycodeTool,
    PunycodeToolInterface,
};

class ToolConfigurator implements ConfiguratorInterface
{
    public function configureContainer(Container $container): void
    {
        $container->bindMany([
            PunycodeToolInterface::class => function(Container $container) {
                return $container->get(PunycodeTool::class);
            },

            DomainTool::class => function(Container $container) {
                return new DomainTool(
                    $container->get(PunycodeToolInterface::class),
                );
            },
        ]);
    }
}
