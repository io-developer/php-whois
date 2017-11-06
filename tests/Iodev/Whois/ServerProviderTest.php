<?php

namespace Iodev\Whois;

use Iodev\Whois\Parsers\CommonParser;

class ServerProviderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param $zone
     * @return Server
     */
    private static function createServer($zone)
    {
        return new Server($zone, "some.host.net", false, new CommonParser());
    }

    /** @var ServerProvider */
    private $provider;


    public function setUp()
    {
        $this->provider = new ServerProvider([]);
    }

    public function tearDown()
    {
    }


    public function testAddOneReturnsSelf()
    {
        $res = $this->provider->addOne(self::createServer(".abc"));
        self::assertSame($this->provider, $res, "Result must be self reference");
    }

    public function testAddReturnsSelf()
    {
        $res = $this->provider->add([ self::createServer(".abc") ]);
        self::assertSame($this->provider, $res, "Result must be self reference");
    }

    public function testMatchEmpty()
    {
        $servers = $this->provider->match("domain.com");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(0, count($servers), "Count must be zero");
    }

    public function testMatchOne()
    {
        $s = self::createServer(".com");
        $this->provider->addOne($s);
        $servers = $this->provider->match("domain.com");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(1, count($servers), "Count must be 1");
        self::assertSame($servers[0], $s, "Wrong matched server");
    }

    public function testMatchSomeViaAddOne()
    {
        $s = self::createServer(".com");
        $this->provider
            ->addOne(self::createServer(".net"))
            ->addOne(self::createServer(".com"))
            ->addOne(self::createServer(".net"))
            ->addOne(self::createServer(".com"))
            ->addOne(self::createServer(".su"))
            ->addOne($s)
            ->addOne(self::createServer(".com"))
            ->addOne(self::createServer(".gov"));

        $servers = $this->provider->match("domain.com");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(4, count($servers), "Count of matched servers not equals");
        self::assertContains($s, $servers, "Server not matched");
    }

    public function testMatchSomeViaConstruct()
    {
        $s = self::createServer(".com");
        $provider = new ServerProvider([
            self::createServer(".net"),
            self::createServer(".com"),
            self::createServer(".net"),
            self::createServer(".com"),
            self::createServer(".su"),
            $s,
            self::createServer(".com"),
            self::createServer(".gov"),
        ]);

        $servers = $provider->match("domain.com");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(4, count($servers), "Count of matched servers not equals");
        self::assertContains($s, $servers, "Server not matched");
    }

    public function testMatchSome()
    {
        $s = self::createServer(".com");
        $this->provider->add([
            self::createServer(".net"),
            self::createServer(".com"),
            self::createServer(".net"),
            self::createServer(".com"),
            self::createServer(".su"),
            $s,
            self::createServer(".com"),
            self::createServer(".gov"),
        ]);

        $servers = $this->provider->match("domain.com");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(4, count($servers), "Count of matched servers not equals");
        self::assertContains($s, $servers, "Server not matched");
    }

    public function testMatchNoneInSome()
    {
        $this->provider->add([
            self::createServer(".net"),
            self::createServer(".com"),
            self::createServer(".net"),
            self::createServer(".com"),
            self::createServer(".su"),
            self::createServer(".com"),
            self::createServer(".gov"),
        ]);

        $servers = $this->provider->match("domain.xyz");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(0, count($servers), "Count of matched servers must be zaro");
    }

    public function testMatchCollisionLongest()
    {
        $this->provider->add([
            self::createServer(".com"),
            self::createServer(".bar.com"),
            self::createServer(".foo.bar.com"),
        ]);
        $servers = $this->provider->match("domain.foo.bar.com");

        self::assertEquals(1, count($servers), "Count of matched servers not equals");
        self::assertEquals(".foo.bar.com", $servers[0]->getZone(), "Invalid matched zone");
    }

    public function testMatchCollisionMiddle()
    {
        $this->provider->add([
            self::createServer(".com"),
            self::createServer(".bar.com"),
            self::createServer(".foo.bar.com"),
        ]);
        $servers = $this->provider->match("domain.bar.com");

        self::assertEquals(1, count($servers), "Count of matched servers not equals");
        self::assertEquals(".bar.com", $servers[0]->getZone(), "Invalid matched zone");
    }

    public function testMatchCollisionShorter()
    {
        $this->provider->add([
            self::createServer(".com"),
            self::createServer(".bar.com"),
            self::createServer(".foo.bar.com"),
        ]);
        $servers = $this->provider->match("domain.com");

        self::assertEquals(1, count($servers), "Count of matched servers not equals");
        self::assertEquals(".com", $servers[0]->getZone(), "Invalid matched zone");
    }

    public function testMatchCollisionMissingZone()
    {
        $this->provider->add([
            self::createServer(".com"),
            self::createServer(".bar.com"),
        ]);
        $servers = $this->provider->match("domain.foo.bar.com");

        self::assertEquals(1, count($servers), "Count of matched servers not equals");
        self::assertEquals(".bar.com", $servers[0]->getZone(), "Invalid matched zone");
    }
}