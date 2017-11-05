<?php

namespace Iodev\Whois;

use FakeSocketLoader;
use Iodev\Whois\Loaders\SocketLoader;

class WhoisTest extends \PHPUnit_Framework_TestCase
{
    /** @var Whois */
    private $whois;

    /** @var ServerProvider */
    private $provider;

    /** @var FakeSocketLoader */
    private $loader;

    private function getWhois()
    {
        $this->provider = new ServerProvider([]);
        $this->loader = new FakeSocketLoader();
        $this->whois = new Whois($this->provider, $this->loader);
        return $this->whois;
    }


    public function testConstruct()
    {
        new Whois(new ServerProvider([]), new SocketLoader());
    }

    public function testGetServerProvider()
    {
        $w = $this->getWhois();
        self::assertSame($this->provider, $w->getServerProvider());
    }

    public function testGetLoader()
    {
        $w = $this->getWhois();
        self::assertSame($this->loader, $w->getLoader());
    }
}
