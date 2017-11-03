<?php

namespace Iodev\Whois;

class DomainInfoTest extends \PHPUnit_Framework_TestCase
{
    public function testConstructEmpty()
    {
        new DomainInfo([]);
    }

    public function testConstructValidSome()
    {
        new DomainInfo([
            "response" => new Response(),
            "domainName" => "foo.bar",
        ]);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testConstructInvalid()
    {
        new DomainInfo([
            "response" => new Response(),
            "foobar" => "foo.bar",
        ]);
    }


    public function testGetResponse()
    {
        $r = new Response();
        $i = new DomainInfo([ "response" => $r ]);
        self::assertSame($r, $i->getResponse());
    }

    public function testGetResponseDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame(null, $i->getResponse());
    }


    public function testGetDomainName()
    {
        $i = new DomainInfo([ "domainName" => "foo.bar" ]);
        self::assertEquals("foo.bar", $i->getDomainName());
    }

    public function testGetDomainNameDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame("", $i->getDomainName());
    }


    public function testGetDomainNameUnicode()
    {
        $i = new DomainInfo([ "domainName" => "foo.bar" ]);
        self::assertEquals("foo.bar", $i->getDomainNameUnicode());
    }

    public function testGetDomainNameUnicodePunnycode()
    {
        $i = new DomainInfo([ "domainName" => "xn--d1acufc.xn--p1ai" ]);
        self::assertEquals("домен.рф", $i->getDomainNameUnicode());
    }

    public function testGetDomainNameUnicodeDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame("", $i->getDomainNameUnicode());
    }


    public function testGetWhoisServer()
    {
        $i = new DomainInfo([ "whoisServer" => "whois.bar" ]);
        self::assertEquals("whois.bar", $i->getWhoisServer());
    }

    public function testGetWhoisServerDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame("", $i->getWhoisServer());
    }


    public function testGetNameServers()
    {
        $i = new DomainInfo([ "nameServers" => [ "a.bar", "b.baz" ] ]);
        self::assertEquals([ "a.bar", "b.baz" ], $i->getNameServers());
    }

    public function testGetNameServersDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame([], $i->getNameServers());
    }


    public function testGetCreationDate()
    {
        $i = new DomainInfo([ "creationDate" => 123456789 ]);
        self::assertEquals(123456789, $i->getCreationDate());
    }

    public function testGetCreationDateDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame(0, $i->getCreationDate());
    }


    public function testGetExpirationDate()
    {
        $i = new DomainInfo([ "expirationDate" => 123456789 ]);
        self::assertEquals(123456789, $i->getExpirationDate());
    }

    public function testGetExpirationDateDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame(0, $i->getExpirationDate());
    }


    public function testGetStates()
    {
        $i = new DomainInfo([ "states" => [ "abc", "def", "ghi" ] ]);
        self::assertEquals([ "abc", "def", "ghi" ], $i->getStates());
    }

    public function testGetStatesDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame([], $i->getStates());
    }


    public function testGetOwner()
    {
        $i = new DomainInfo([ "owner" => "Some Company" ]);
        self::assertEquals("Some Company", $i->getOwner());
    }

    public function testGetOwnerDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame("", $i->getOwner());
    }


    public function testGetRegistrar()
    {
        $i = new DomainInfo([ "registrar" => "Some Registrar" ]);
        self::assertEquals("Some Registrar", $i->getRegistrar());
    }

    public function testGetRegistrarDefault()
    {
        $i = new DomainInfo([]);
        self::assertSame("", $i->getRegistrar());
    }
}
