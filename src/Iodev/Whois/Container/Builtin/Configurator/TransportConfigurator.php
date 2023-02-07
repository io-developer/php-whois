<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin\Configurator;

use \Iodev\Whois\Container\Builtin\Container;
use \Iodev\Whois\Transport\{
    Transport,
    Middleware\PrintLog,
    Middleware\Response\EncodingProcessor,
    Middleware\Response\RateLimitChecker,
    Loader\LoaderInterface,
    Loader\SocketLoader,
};
use \Iodev\Whois\Tool\{
    TextTool,
};

class TransportConfigurator implements ConfiguratorInterface
{
    public function configureContainer(Container $container): void
    {
        $container->bindMany([
            Transport::class => function(Container $container, string $id) {
                return (new Transport(
                        $container->get(LoaderInterface::class),
                    ))
                    ->setRequestMiddlewares([
                        $container->get(PrintLog::class),
                    ])
                    ->setResponseMiddlewares([
                        $container->get(EncodingProcessor::class),
                        $container->get(RateLimitChecker::class),
                        $container->get(PrintLog::class),
                    ])
                ;
            },
    
            LoaderInterface::class => function(Container $container, string $id) {
                return $container->get(SocketLoader::class);
            },
            
            EncodingProcessor::class => function(Container $container, string $id) {
                return new EncodingProcessor(
                    $container->get(TextTool::class),
                );
            },
        ]);
    }
}
