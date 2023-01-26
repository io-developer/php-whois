<?php

declare(strict_types=1);

namespace Iodev\Whois;

use Iodev\Whois\Container\Default\ContainerBuilder;
use Iodev\Whois\Loader\FakeSocketLoader;
use Iodev\Whois\Loader\ILoader;
use Iodev\Whois\Tool\TextTool;
use PHPUnit\Framework\TestCase;

class WhoisTest extends TestCase
{
    private Whois $whois;

    private FakeSocketLoader $loader;

    private function createWhois(): Whois
    {
        $container = (new ContainerBuilder())
            ->configure()
            ->getContainer()
        ;
        $this->loader = new FakeSocketLoader(
            $container->get(TextTool::class),
            60,
        );
        $container->bind(ILoader::class, fn() => $this->loader);

        $this->whois = $container->get(Whois::class);

        return $this->whois;
    }

    public function testConstruct()
    {
        $instance = $this->createWhois();
        $this->assertInstanceOf(Whois::class, $instance);
    }
}
