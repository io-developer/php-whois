<?php

namespace Iodev\Whois;

use Iodev\Whois\Exceptions\ConnectionException;
use Tools\FakeSocketLoader;

class WhoisTest extends \PHPUnit_Framework_TestCase
{
    /** @var Whois */
    private $whois;

    /** @var FakeSocketLoader */
    private $loader;

    public function setUp()
    {
        $this->loader = new FakeSocketLoader();
        $this->whois = new Whois($this->loader);
    }

    public function tearDown()
    {
    }

    public function testConstruct()
    {
        self::assertInstanceOf(Whois::class, new Whois(new FakeSocketLoader()));
    }

    public function testAddServerReturnsSelf()
    {
        $res = $this->whois->addServer(new Server(".abc"));
        self::assertSame($this->whois, $res, "Result must be self reference");
    }

    public function testMatchServersEmpty()
    {
        $servers = $this->whois->matchServers("domain.com");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(0, count($servers), "Count must be zero");
    }

    public function testMatchServersOne()
    {
        $s = new Server(".com");
        $this->whois->addServer($s);
        $servers = $this->whois->matchServers("domain.com");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(1, count($servers), "Count must be 1");
        self::assertSame($servers[0], $s, "Wrong matched server");
    }

    public function testMatchServersSome()
    {
        $s = new Server(".com");
        $this->whois
            ->addServer(new Server(".net"))
            ->addServer(new Server(".com"))
            ->addServer(new Server(".net"))
            ->addServer(new Server(".com"))
            ->addServer(new Server(".su"))
            ->addServer($s)
            ->addServer(new Server(".com"))
            ->addServer(new Server(".gov"));

        $servers = $this->whois->matchServers("domain.com");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(4, count($servers), "Count of matched servers not equals");
        self::assertContains($s, $servers, "Server not matched");
    }

    public function testMatchServersNoneInSome()
    {
        $this->whois
            ->addServer(new Server(".net"))
            ->addServer(new Server(".com"))
            ->addServer(new Server(".net"))
            ->addServer(new Server(".com"))
            ->addServer(new Server(".su"))
            ->addServer(new Server(".com"))
            ->addServer(new Server(".gov"));

        $servers = $this->whois->matchServers("domain.xyz");
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(0, count($servers), "Count of matched servers must be zaro");
    }
}
