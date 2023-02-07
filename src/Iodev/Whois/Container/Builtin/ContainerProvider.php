<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin;

use \Iodev\Whois\Container\Builtin\Configurator\{
    ConfigConfigurator,
    ModuleAsnConfigurator,
    ModuleTldConfigurator,
    RootConfigurator,
    ToolConfigurator,
    TransportConfigurator,
};

class ContainerProvider
{
    protected ?Container $container = null;
    protected ?ContainerBuilder $containerBuilder = null;

    public static function get(): static
    {
        static $instance = null;

        if ($instance === null) {
            $instance = new static();
        }
        return $instance;
    }

    public function getContainer(): Container
    {
        if ($this->container === null) {
            $this->container = $this->createContainer();
        }
        return $this->container;
    }

    public function createContainer(): Container
    {
        return $this->getContainerBuilder()->build();
    }

    public function getContainerBuilder(): ContainerBuilder
    {
        if ($this->containerBuilder === null) {
            $this->containerBuilder = $this->createContainerBuilder();
        }
        return $this->containerBuilder;
    }

    public function createContainerBuilder(): ContainerBuilder
    {
        return (new ContainerBuilder())->setConfigurators([
            new RootConfigurator(),
            new ConfigConfigurator(),
            new ToolConfigurator(),
            new TransportConfigurator(),
            new ModuleAsnConfigurator(),
            new ModuleTldConfigurator(),
        ]);
    }
}
