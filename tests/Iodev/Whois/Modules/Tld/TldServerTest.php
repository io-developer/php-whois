<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Container\Default\ContainerBuilder;
use Iodev\Whois\Modules\Tld\Parsers\TestCommonParser;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Tool\ParserTool;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

class TldServerTest extends TestCase
{
    private ContainerInterface $container;
    private TldServerProviderInterface $tldServerProvider;
    private TldParser $parser;

    public function __construct()
    {
        parent::__construct();

        $this->container = (new ContainerBuilder())->configure()->getContainer();
        $this->container->bind(TestCommonParser::class, function() {
            return new TestCommonParser(
                $this->container->get(ParserTool::class),
                $this->container->get(DomainTool::class),
                $this->container->get(DateTool::class),
            );
        });

        $this->tldServerProvider = $this->container->get(TldServerProviderInterface::class);

        $this->parser = $this->container->get($this->getParserClass());
        $this->container->bind(TldParser::class, function() {
            return $this->parser;
        });
    }

    private function getServerClass()
    {
        return TldServer::class;
    }

    private function getParser()
    {
        return $this->parser;
    }

    private function getParserClass(): string
    {
        return TestCommonParser::class;
    }


    public function testIsDomainZoneValid()
    {
        $s = new TldServer(".abc", "some.host.com", false, $this->getParser(), "%s\r\n");
        self::assertTrue($s->isDomainZone("some.abc"));
    }

    public function testIsDomainZoneValidComplex()
    {
        $s = new TldServer(".abc", "some.host.com", false, $this->getParser(), "%s\r\n");
        self::assertTrue($s->isDomainZone("some.foo.bar.abc"));
    }

    public function testIsDomainZoneInvalid()
    {
        $s = new TldServer(".abc", "some.host.com", false, $this->getParser(), "%s\r\n");
        self::assertFalse($s->isDomainZone("some.com"));
    }

    public function testIsDomainZoneInvalidEnd()
    {
        $s = new TldServer(".foo.bar", "some.host.com", false, $this->getParser(), "%s\r\n");
        self::assertFalse($s->isDomainZone("some.bar"));
    }

    public function testBuildDomainQueryCustom()
    {
        $s = new TldServer(".foo.bar", "some.host.com", false, $this->getParser(), "prefix %s suffix\r\n");
        self::assertEquals("prefix domain.com suffix\r\n", $s->buildDomainQuery("domain.com"));
    }

    public function testBuildDomainQueryCustomNoParam()
    {
        $s = new TldServer(".foo.bar", "some.host.com", false, $this->getParser(), "prefix suffix\r\n");
        self::assertEquals("prefix suffix\r\n", $s->buildDomainQuery("domain.com"));
    }

    public function testFromDataFullArgs()
    {
        $s = $this->tldServerProvider->create([
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
        $s = $this->tldServerProvider->create([
            'zone' => '.abc',
            'host' => 'some.host',
            'parser' => $this->getParser(),
        ]);

        self::assertEquals(".abc", $s->zone);
        self::assertEquals("some.host", $s->host);
        self::assertFalse($s->centralized);
        self::assertInstanceOf($this->getParserClass(), $s->parser);
    }

    public function testFromDataMissingZone()
    {
        $this->expectException('\InvalidArgumentException');
        $this->tldServerProvider->create([ "host" => "some.host" ]);
    }

    public function testFromDataMissingHost()
    {
        $this->expectException('\InvalidArgumentException');
        $this->tldServerProvider->create([ "zone" => ".abc" ]);
    }

    public function testFromDataMissingAll()
    {
        $this->expectException('\InvalidArgumentException');
        $this->tldServerProvider->create([]);
    }

    public function testFromDataListOne()
    {
        $s = $this->tldServerProvider->createMany([
            [ "zone" => ".abc", "host" => "some.host" ],
        ]);
        self::assertTrue(is_array($s), "Array expected");
        self::assertEquals(1, count($s));
        self::assertInstanceOf($this->getServerClass(), $s[0]);
        self::assertEquals(".abc", $s[0]->zone);
        self::assertEquals("some.host", $s[0]->host);
        self::assertInstanceOf($this->getParserClass(), $s[0]->parser);
    }

    public function testFromDataListTwo()
    {
        $s = $this->tldServerProvider->createMany([
            [ "zone" => ".abc", "host" => "some.host" ],
            [ "zone" => ".cde", "host" => "other.host", "centralized" => true, "queryFormat" => "prefix %s suffix\r\n" ],
        ]);
        self::assertTrue(is_array($s), "Array expected");
        self::assertEquals(2, count($s));

        self::assertInstanceOf($this->getServerClass(), $s[0]);
        self::assertEquals(".abc", $s[0]->zone);
        self::assertEquals("some.host", $s[0]->host);
        self::assertFalse($s[0]->centralized);
        self::assertInstanceOf($this->getParserClass(), $s[0]->parser);

        self::assertInstanceOf($this->getServerClass(), $s[1]);
        self::assertEquals(".cde", $s[1]->zone);
        self::assertEquals("other.host", $s[1]->host);
        self::assertTrue($s[1]->centralized);
        self::assertInstanceOf($this->getParserClass(), $s[1]->parser);
        self::assertEquals("prefix %s suffix\r\n", $s[1]->queryFormat);
    }
}
