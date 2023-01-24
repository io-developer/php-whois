<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Container\Default\ContainerBuilder;
use Iodev\Whois\Factory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

class TldServerTest extends TestCase
{
    private ContainerInterface $container;
    private TldParserProviderInterface $tldParserProvider;

    public function __construct()
    {
        parent::__construct();

        $this->container = (new ContainerBuilder())->configure()->getContainer();
        $this->tldParserProvider = $this->container->get(TldParserProviderInterface::class);
    }

    private function getServerClass()
    {
        return '\Iodev\Whois\Modules\Tld\TldServer';
    }

    private function getParser()
    {
        return $this->tldParserProvider->getByClassName($this->getParserClass());
    }

    private function getParserClass(): string
    {
        return '\Iodev\Whois\Modules\Tld\Parsers\TestCommonParser';
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
        $s = Factory::get()->createTldSever([
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
        $s = Factory::get()->createTldSever([ "zone" => ".abc", "host" => "some.host" ], $this->getParser());

        self::assertEquals(".abc", $s->zone);
        self::assertEquals("some.host", $s->host);
        self::assertFalse($s->centralized);
        self::assertInstanceOf($this->getParserClass(), $s->parser);
    }

    public function testFromDataMissingZone()
    {
        $this->expectException('\InvalidArgumentException');
        Factory::get()->createTldSever([ "host" => "some.host" ], $this->getParser());
    }

    public function testFromDataMissingHost()
    {
        $this->expectException('\InvalidArgumentException');
        Factory::get()->createTldSever([ "zone" => ".abc" ], $this->getParser());
    }

    public function testFromDataMissingAll()
    {
        $this->expectException('\InvalidArgumentException');
        Factory::get()->createTldSever([], $this->getParser());
    }

    public function testFromDataListOne()
    {
        $s = Factory::get()->createTldSevers(
            [ [ "zone" => ".abc", "host" => "some.host" ] ],
            self::getParser()
        );
        self::assertTrue(is_array($s), "Array expected");
        self::assertEquals(1, count($s));
        self::assertInstanceOf($this->getServerClass(), $s[0]);
        self::assertEquals(".abc", $s[0]->zone);
        self::assertEquals("some.host", $s[0]->host);
        self::assertInstanceOf($this->getParserClass(), $s[0]->parser);
    }

    public function testFromDataListTwo()
    {
        $s = Factory::get()->createTldSevers([
                [ "zone" => ".abc", "host" => "some.host" ],
                [ "zone" => ".cde", "host" => "other.host", "centralized" => true, "queryFormat" => "prefix %s suffix\r\n" ],
            ],
            self::getParser()
        );
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
