<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Whois;

use Iodev\Whois\BaseTestCase;
use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Module\Tld\Parsing\ParserInterface;
use Iodev\Whois\Module\Tld\Parsing\ParserProviderInterface;
use Iodev\Whois\Module\Tld\Parsing\TestCommonParser;

class ServerProviderTest extends BaseTestCase
{
    private TestCommonParser $parser;
    protected ParserProviderInterface $parserProvider;
    private ServerProvider $serverProvider;
    protected ServerCollection $serverCol;

    protected function onConstructed()
    {
        $this->parser = $this->container->get(TestCommonParser::class);
        $this->container->bind(ParserInterface::class, function() {
            return $this->parser;
        });

        $this->parserProvider = $this->container->get(ParserProviderInterface::class);
    }

    public function setUp(): void
    {
        $this->serverProvider = $this->container->get(ServerProvider::class);

        $this->serverCol = $this->serverProvider->getCollection();
        $this->serverCol->setList([]);
    }
    
    private function getParserClass(): string
    {
        return $this->parser::class;
    }

    protected function createServer(string $zone): WhoisServer
    {
        return new WhoisServer($zone, 'some.host.net', false, $this->parser, "%s\r\n", 0);
    }

    public function testFromDataFullArgs()
    {
        $s = $this->serverProvider->fromConfig([
            'zone' => '.abc',
            'host' => 'some.host',
            'centralized' => true,
            'parserClass' => $this->getParserClass(),
            'queryFormat' => "prefix %s suffix\r\n",
        ]);

        self::assertEquals('.abc', $s->zone);
        self::assertEquals('some.host', $s->host);
        self::assertTrue($s->centralized);
        self::assertInstanceOf($this->getParserClass(), $s->parser);
        self::assertEquals("prefix %s suffix\r\n", $s->queryFormat);
    }

    public function testFromDataZoneHostOnly()
    {
        $s = $this->serverProvider->fromConfig([
            'zone' => '.abc',
            'host' => 'some.host',
            'parser' => $this->parser,
        ]);

        self::assertEquals(".abc", $s->zone);
        self::assertEquals("some.host", $s->host);
        self::assertFalse($s->centralized);
        self::assertInstanceOf($this->parser::class, $s->parser);
    }

    public function testFromDataMissingZone()
    {
        $this->expectException('\InvalidArgumentException');
        $this->serverProvider->fromConfig([ 'host' => 'some.host' ]);
    }

    public function testFromDataMissingHost()
    {
        $this->expectException('\InvalidArgumentException');
        $this->serverProvider->fromConfig([ 'zone' => '.abc' ]);
    }

    public function testFromDataMissingAll()
    {
        $this->expectException('\InvalidArgumentException');
        $this->serverProvider->fromConfig([]);
    }

    public function testFromDataListOne()
    {
        $s = [
            $this->serverProvider->fromConfig([
                'zone' => '.abc',
                'host' => 'some.host',
            ]),
        ];
        self::assertTrue(is_array($s), 'Array expected');
        self::assertEquals(1, count($s));
        self::assertInstanceOf(WhoisServer::class, $s[0]);
        self::assertEquals('.abc', $s[0]->zone);
        self::assertEquals('some.host', $s[0]->host);
        self::assertInstanceOf($this->getParserClass(), $s[0]->parser);
    }

    public function testFromDataListTwo()
    {
        $s = [
            $this->serverProvider->fromConfig([
                'zone' => '.abc',
                'host' => 'some.host',
            ]),
            $this->serverProvider->fromConfig([
                'zone' => '.cde',
                'host' => 'other.host',
                'centralized' => true,
                'queryFormat' => "prefix %s suffix\r\n",
            ]),
        ];
        self::assertTrue(is_array($s), "Array expected");
        self::assertEquals(2, count($s));

        self::assertInstanceOf(WhoisServer::class, $s[0]);
        self::assertEquals('.abc', $s[0]->zone);
        self::assertEquals('some.host', $s[0]->host);
        self::assertFalse($s[0]->centralized);
        self::assertInstanceOf($this->getParserClass(), $s[0]->parser);

        self::assertInstanceOf(WhoisServer::class, $s[1]);
        self::assertEquals('.cde', $s[1]->zone);
        self::assertEquals('other.host', $s[1]->host);
        self::assertTrue($s[1]->centralized);
        self::assertInstanceOf($this->getParserClass(), $s[1]->parser);
        self::assertEquals("prefix %s suffix\r\n", $s[1]->queryFormat);
    }




    public function testAddServersReturnsSelf()
    {
        $res = $this->serverCol->addList([$this->createServer(".abc")]);
        self::assertSame( $this->serverCol, $res, "Result must be self reference");
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
