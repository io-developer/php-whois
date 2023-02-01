<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld;

use Iodev\Whois\BaseTestCase;
use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Module\Tld\Parsing\ParserInterface;
use Iodev\Whois\Module\Tld\Parsing\TestCommonParser;
use Iodev\Whois\Module\Tld\Whois\ServerMatcher;
use Iodev\Whois\Module\Tld\Whois\ServerProvider;

class WhoisServerTest extends BaseTestCase
{
    private ServerProvider $tldServerProvider;
    private ServerMatcher $tldServerMatcher;
    private TestCommonParser $parser;

    protected function onConstructed()
    {
        $this->tldServerProvider = $this->container->get(ServerProvider::class);
        $this->tldServerMatcher = $this->container->get(ServerMatcher::class);

        $this->parser = $this->container->get(TestCommonParser::class);

        $this->container->bind(ParserInterface::class, function() {
            return $this->parser;
        });
    }

    private function getParserClass(): string
    {
        return $this->parser::class;
    }


    public function testIsDomainZoneValid()
    {
        $s = new WhoisServer(".abc", "some.host.com", false, $this->parser, "%s\r\n", 0);
        self::assertTrue($this->tldServerMatcher->isDomainZone($s, "some.abc"));
    }

    public function testIsDomainZoneValidComplex()
    {
        $s = new WhoisServer(".abc", "some.host.com", false, $this->parser, "%s\r\n", 0);
        self::assertTrue($this->tldServerMatcher->isDomainZone($s, "some.foo.bar.abc"));
    }

    public function testIsDomainZoneInvalid()
    {
        $s = new WhoisServer(".abc", "some.host.com", false, $this->parser, "%s\r\n", 0);
        self::assertFalse($this->tldServerMatcher->isDomainZone($s, "some.com"));
    }

    public function testIsDomainZoneInvalidEnd()
    {
        $s = new WhoisServer(".foo.bar", "some.host.com", false, $this->parser, "%s\r\n", 0);
        self::assertFalse($this->tldServerMatcher->isDomainZone($s, "some.bar"));
    }

    public function testBuildDomainQueryCustom()
    {
        $s = new WhoisServer(".foo.bar", "some.host.com", false, $this->parser, "prefix %s suffix\r\n", 0);
        self::assertEquals("prefix domain.com suffix\r\n", $s->buildDomainQuery("domain.com"));
    }

    public function testBuildDomainQueryCustomNoParam()
    {
        $s = new WhoisServer(
            ".foo.bar", "some.host.com", false, $this->parser, "prefix suffix\r\n", 0);
        self::assertEquals("prefix suffix\r\n", $s->buildDomainQuery("domain.com"));
    }

    public function testFromDataFullArgs()
    {
        $s = $this->tldServerProvider->fromConfig([
            "zone" => ".abc",
            "host" => "some.host",
            "centralized" => true,
            "parserClass" => $this->getParserClass(),
            "queryFormat" => "prefix %s suffix\r\n",
        ]);

        self::assertEquals(".abc", $s->zone);
        self::assertEquals("some.host", $s->host);
        self::assertTrue($s->centralized);
        self::assertInstanceOf($this->getParserClass(), $s->parser);
        self::assertEquals("prefix %s suffix\r\n", $s->queryFormat);
    }

    public function testFromDataZoneHostOnly()
    {
        $s = $this->tldServerProvider->fromConfig([
            'zone' => '.abc',
            'host' => 'some.host',
            'parser' => $this->parser,
        ]);

        self::assertEquals(".abc", $s->zone);
        self::assertEquals("some.host", $s->host);
        self::assertFalse($s->centralized);
        self::assertInstanceOf($this->getParserClass(), $s->parser);
    }

    public function testFromDataMissingZone()
    {
        $this->expectException('\InvalidArgumentException');
        $this->tldServerProvider->fromConfig([ "host" => "some.host" ]);
    }

    public function testFromDataMissingHost()
    {
        $this->expectException('\InvalidArgumentException');
        $this->tldServerProvider->fromConfig([ "zone" => ".abc" ]);
    }

    public function testFromDataMissingAll()
    {
        $this->expectException('\InvalidArgumentException');
        $this->tldServerProvider->fromConfig([]);
    }

    public function testFromDataListOne()
    {
        $s = [
            $this->tldServerProvider->fromConfig([
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
            $this->tldServerProvider->fromConfig([
                'zone' => '.abc',
                'host' => 'some.host',
            ]),
            $this->tldServerProvider->fromConfig([
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
}
