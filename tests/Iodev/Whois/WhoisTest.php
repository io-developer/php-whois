<?php

declare(strict_types=1);

namespace Iodev\Whois;

use Iodev\Whois\Loaders\FakeSocketLoader;
use Iodev\Whois\Loaders\SocketLoader;
use PHPUnit\Framework\TestCase;

class WhoisTest extends TestCase
{
    /** @var Whois */
    private $whois;

    /** @var FakeSocketLoader */
    private $loader;

    /**
     * @return Whois
     */
    private function getWhois()
    {
        $this->loader = new FakeSocketLoader();
        $this->whois = new Whois($this->loader);
        return $this->whois;
    }

    public function testConstruct()
    {
        $instance = new Whois(new SocketLoader());
        $this->assertInstanceOf(Whois::class, $instance);
    }

    public function testGetLoader()
    {
        $w = $this->getWhois();
        self::assertSame($this->loader, $w->getLoader());
    }
}
