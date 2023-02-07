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
    protected static $defaultInstance = null;

    protected ?Container $container = null;
    protected ?ContainerBuilder $containerBuilder = null;

    public static function get(): static
    {
        if (static::$defaultInstance === null) {
            static::$defaultInstance = new static();
        }
        return static::$defaultInstance;
    }

    public function getContainer(): Container
    {
        if ($this->container === null) {
            $this->container = $this->createContainer();
        }
        return $this->container;
    }


    public static function getDefaultContainer(): Container
    {
        return static::get()->getContainer();
    }    public function createContainer(): Container
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
