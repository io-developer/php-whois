<?php

declare(strict_types=1);

namespace Iodev\Whois;

use Iodev\Whois\Punycode\IPunycode;
use Iodev\Whois\Container\Default\ContainerBuilder;
use Psr\Container\ContainerInterface;

class Factory implements IFactory
{
    private ContainerInterface $container;

    public function __construct()
    {
        $this->container = (new ContainerBuilder())
            ->configure()
            ->getContainer()
        ;
    }

    public static function get(): Factory
    {
        static $instance;
        if (!$instance) {
            $instance = new static();
        }
        return $instance;
    }

    public function createPunycode(): IPunycode
    {
        return $this->container->get(IPunycode::class);
    }
}
