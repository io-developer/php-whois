<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Factory;
use PHPUnit\Framework\TestCase;

class TldServerTest extends TestCase
{
    private static function getServerClass()
    {
        return '\Iodev\Whois\Modules\Tld\TldServer';
    }

    private static function getParser()
    {
        return Factory::get()->createTldParserByClass(self::getParserClass());
    }

    private static function getParserClass()
    {
        return '\Iodev\Whois\Modules\Tld\Parsers\TestCommonParser';
    }


    public function testIsDomainZoneValid()
    {
        $s = new TldServer(".abc", "some.host.com", false, self::getParser(), "%s\r\n");
        self::assertTrue($s->isDomainZone("some.abc"));
    }

    public function testIsDomainZoneValidComplex()
    {
        $s = new TldServer(".abc", "some.host.com", false, self::getParser(), "%s\r\n");
        self::assertTrue($s->isDomainZone("some.foo.bar.abc"));
    }

    public function testIsDomainZoneInvalid()
    {
        $s = new TldServer(".abc", "some.host.com", false, self::getParser(), "%s\r\n");
        self::assertFalse($s->isDomainZone("some.com"));
    }

    public function testIsDomainZoneInvalidEnd()
    {
        $s = new TldServer(".foo.bar", "some.host.com", false, self::getParser(), "%s\r\n");
        self::assertFalse($s->isDomainZone("some.bar"));
    }

    public function testBuildDomainQueryCustom()
    {
        $s = new TldServer(".foo.bar", "some.host.com", false, self::getParser(), "prefix %s suffix\r\n");
        self::assertEquals("prefix domain.com suffix\r\n", $s->buildDomainQuery("domain.com"));
    }

    public function testBuildDomainQueryCustomNoParam()
    {
        $s = new TldServer(".foo.bar", "some.host.com", false, self::getParser(), "prefix suffix\r\n");
        self::assertEquals("prefix suffix\r\n", $s->buildDomainQuery("domain.com"));
    }

    public function testFromDataFullArgs()
    {
        $s = Factory::get()->createTldSever([
            "zone" => ".abc",
            "host" => "some.host",
            "centralized" => true,
            "parserClass" => self::getParserClass(),
            "queryFormat" => "prefix %s suffix\r\n",
        ]);

        self::assertEquals(".abc", $s->zone);
        self::assertEquals("some.host", $s->host);
        self::assertTrue($s->centralized);
        self::assertInstanceOf(self::getParserClass(), $s->parser);
        self::assertEquals("prefix %s suffix\r\n", $s->queryFormat);
    }

    public function testFromDataZoneHostOnly()
    {
        $s = Factory::get()->createTldSever([ "zone" => ".abc", "host" => "some.host" ], self::getParser());

        self::assertEquals(".abc", $s->zone);
        self::assertEquals("some.host", $s->host);
        self::assertFalse($s->centralized);
        self::assertInstanceOf(self::getParserClass(), $s->parser);
    }

    public function testFromDataMissingZone()
    {
        $this->expectException('\InvalidArgumentException');
        Factory::get()->createTldSever([ "host" => "some.host" ], self::getParser());
    }

    public function testFromDataMissingHost()
    {
        $this->expectException('\InvalidArgumentException');
        Factory::get()->createTldSever([ "zone" => ".abc" ], self::getParser());
    }

    public function testFromDataMissingAll()
    {
        $this->expectException('\InvalidArgumentException');
        Factory::get()->createTldSever([], self::getParser());
    }

    public function testFromDataListOne()
    {
        $s = Factory::get()->createTldSevers(
            [ [ "zone" => ".abc", "host" => "some.host" ] ],
            self::getParser()
        );
        self::assertTrue(is_array($s), "Array expected");
        self::assertEquals(1, count($s));
        self::assertInstanceOf(self::getServerClass(), $s[0]);
        self::assertEquals(".abc", $s[0]->zone);
        self::assertEquals("some.host", $s[0]->host);
        self::assertInstanceOf(self::getParserClass(), $s[0]->parser);
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

        self::assertInstanceOf(self::getServerClass(), $s[0]);
        self::assertEquals(".abc", $s[0]->zone);
        self::assertEquals("some.host", $s[0]->host);
        self::assertFalse($s[0]->centralized);
        self::assertInstanceOf(self::getParserClass(), $s[0]->parser);

        self::assertInstanceOf(self::getServerClass(), $s[1]);
        self::assertEquals(".cde", $s[1]->zone);
        self::assertEquals("other.host", $s[1]->host);
        self::assertTrue($s[1]->centralized);
        self::assertInstanceOf(self::getParserClass(), $s[1]->parser);
        self::assertEquals("prefix %s suffix\r\n", $s[1]->queryFormat);
    }
}
