<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\BaseTestCase;

class TldModuleServerTest extends BaseTestCase
{
    protected TldParserProviderInterface $parserProvider;
    protected TldModule $tldModule;
    protected TldServerCollection $serverCol;
    protected TldServerProviderInterface $serverProvider;

    protected function onConstructed()
    {
        $this->parserProvider = $this->container->get(TldParserProviderInterface::class);
    }

    protected function createServer(string $zone): TldServer
    {
        $parser = $this->parserProvider->getDefault();

        return new TldServer($zone, "some.host.net", false, $parser, "%s\r\n");
    }

    public function setUp(): void
    {
        $this->tldModule = $this->container->get(TldModule::class);

        $this->serverProvider = $this->tldModule->getServerProvider();

        $this->serverCol = $this->serverProvider->getCollection();
        $this->serverCol->setList([]);
    }

    public function tearDown(): void
    {
    }


    public function testAddServersReturnsSelf()
    {
        $res = $this->serverCol->addList([$this->createServer(".abc")]);
        self::assertSame($this->tldModule->getServerProvider()->getCollection(), $res, "Result must be self reference");
    }

    public function testMatchServersQuietEmpty()
    {
        $servers = $this->serverProvider->getMatched('domain.com');
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(0, count($servers), "Count must be zero");
    }

    public function testMatchServersOne()
    {
        $s = $this->createServer(".com");
        $this->serverCol->addList([$s]);
        $servers = $this->serverProvider->getMatched('domain.com');
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(1, count($servers), "Count must be 1");
        self::assertSame($servers[0], $s, "Wrong matched server");
    }

    public function testMatchServersSome()
    {
        $s = $this->createServer(".com");
        $this->serverCol->addList([
            $this->createServer(".net"),
            $this->createServer(".com"),
            $this->createServer(".net"),
            $this->createServer(".com"),
            $this->createServer(".su"),
            $s,
            $this->createServer(".com"),
            $this->createServer(".gov"),
        ]);

        $servers = $this->serverProvider->getMatched('domain.com');
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(4, count($servers), "Count of matched servers not equals");
        self::assertContains($s, $servers, "Server not matched");
    }

    public function testMatchServersQuietNoneInSome()
    {
        $this->serverCol->addList([
            $this->createServer(".net"),
            $this->createServer(".com"),
            $this->createServer(".net"),
            $this->createServer(".com"),
            $this->createServer(".su"),
            $this->createServer(".com"),
            $this->createServer(".gov"),
        ]);

        $servers = $this->serverProvider->getMatched('domain.xyz');
        self::assertTrue(is_array($servers), "Result must be Array");
        self::assertEquals(0, count($servers), "Count of matched servers must be zaro");
    }

    public function testMatchServersCollisionLongest()
    {
        $this->serverCol->addList([
            $this->createServer(".com"),
            $this->createServer(".bar.com"),
            $this->createServer(".foo.bar.com"),
        ]);
        $servers = $this->serverProvider->getMatched('domain.foo.bar.com');

        self::assertEquals(3, count($servers), "Count of matched servers not equals");
        self::assertEquals(".foo.bar.com", $servers[0]->zone, "Invalid matched zone");
        self::assertEquals(".bar.com", $servers[1]->zone, "Invalid matched zone");
        self::assertEquals(".com", $servers[2]->zone, "Invalid matched zone");
    }

    public function testMatchServersCollisionMiddle()
    {
        $this->serverCol->addList([
            $this->createServer(".com"),
            $this->createServer(".bar.com"),
            $this->createServer(".foo.bar.com"),
        ]);
        $servers = $this->serverProvider->getMatched('domain.bar.com');

        self::assertEquals(2, count($servers), "Count of matched servers not equals");
        self::assertEquals(".bar.com", $servers[0]->zone, "Invalid matched zone");
        self::assertEquals(".com", $servers[1]->zone, "Invalid matched zone");
    }

    public function testMatchServersCollisionShorter()
    {
        $this->serverCol->addList([
            $this->createServer(".com"),
            $this->createServer(".bar.com"),
            $this->createServer(".foo.bar.com"),
        ]);
        $servers = $this->serverProvider->getMatched('domain.com');

        self::assertEquals(1, count($servers), "Count of matched servers not equals");
        self::assertEquals(".com", $servers[0]->zone, "Invalid matched zone");
    }

    public function testMatchServersCollisiondWildcard()
    {
        $this->serverCol->addList([
            $this->createServer(".com"),
            $this->createServer(".*.com"),
        ]);
        $servers = $this->serverProvider->getMatched('domain.com');

        self::assertEquals(1, count($servers), "Count of matched servers not equals");
        self::assertEquals(".com", $servers[0]->zone, "Invalid matched zone");
    }

    public function testMatchServersCollisionMissingZone()
    {
        $this->serverCol->addList([
            $this->createServer(".com"),
            $this->createServer(".bar.com"),
        ]);
        $servers = $this->serverProvider->getMatched('domain.foo.bar.com');

        self::assertEquals(2, count($servers), "Count of matched servers not equals");
        self::assertEquals(".bar.com", $servers[0]->zone, "Invalid matched zone");
        self::assertEquals(".com", $servers[1]->zone, "Invalid matched zone");
    }

    public function testMatchServersCollisionFallback()
    {
        $this->serverCol->addList([
            $this->createServer(".*"),
            $this->createServer(".*.foo"),
            $this->createServer(".*.com"),
            $this->createServer(".bar.*"),
            $this->createServer(".foo.*.*"),
            $this->createServer(".bar.com"),
        ]);
        $servers = $this->serverProvider->getMatched('domain.foo.bar.com');

        self::assertEquals(5, count($servers), "Count of matched servers not equals");
        self::assertEquals(".foo.*.*", $servers[0]->zone, "Invalid matched zone");
        self::assertEquals(".bar.com", $servers[1]->zone, "Invalid matched zone");
        self::assertEquals(".bar.*", $servers[2]->zone, "Invalid matched zone");
        self::assertEquals(".*.com", $servers[3]->zone, "Invalid matched zone");
        self::assertEquals(".*", $servers[4]->zone, "Invalid matched zone");
    }

    public function testMatchServersDuplicatesOrder()
    {
        $first = $this->createServer(".com");
        $second = $this->createServer(".com");
        $third = $this->createServer(".com");

        $this->serverCol->addList([
            $first,
            $second,
            $third,
        ]);
        $matched = $this->serverProvider->getMatched('domain.foo.bar.com');

        self::assertEquals(3, count($matched));
        self::assertSame($matched[0], $first);
        self::assertSame($matched[1], $second);
        self::assertSame($matched[2], $third);
    }
}
