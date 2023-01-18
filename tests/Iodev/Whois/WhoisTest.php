<?php

declare(strict_types=1);

namespace Iodev\Whois;

use Iodev\Whois\Container\Default\ContainerBuilder;
use Iodev\Whois\Loaders\FakeSocketLoader;
use Iodev\Whois\Loaders\ILoader;
use PHPUnit\Framework\TestCase;

class WhoisTest extends TestCase
{
    private Whois $whois;

    private FakeSocketLoader $loader;

    private function createWhois(): Whois
    {
        $this->loader = new FakeSocketLoader();

        $container = (new ContainerBuilder())
            ->configure()
            ->getContainer()
            ->bind(ILoader::class, fn() => $this->loader)
        ;
        $this->whois = $container->get(Whois::class);

        return $this->whois;
    }

    public function testConstruct()
    {
        $instance = $this->createWhois();
        $this->assertInstanceOf(Whois::class, $instance);
    }
}
