<?php

declare(strict_types=1);

namespace Iodev\Whois\Container\Builtin;

use \Iodev\Whois\Container\Builtin\Configurator\ConfiguratorInterface;

class ContainerBuilder
{
    /** @var ConfiguratorInterface[] */
    protected array $configurators = [];

    public function setConfigurators(array $configurators): static
    {
        foreach ($configurators as $configurator) {
            $this->addConfigurator($configurator);
        }
        return $this;
    }

    public function addConfigurator(ConfiguratorInterface $configurator): static
    {
        $this->configurators[] = $configurator;
        return $this;
    }

    public function build(): Container
    {
        $container = new Container();

        foreach ($this->configurators as $configurator) {
            $configurator->configureContainer($container);
        }

        return $container;
    }
}
