<?php

namespace Iodev\Whois;

class ResponseTest extends \PHPUnit_Framework_TestCase
{
    /** @var Response */
    private $resp;

    public function setUp()
    {
        $this->resp = new Response(ResponseType::DOMAIN, "domain.some", "Test content", "whois.host.abc");
    }


    public function testGetDomain()
    {
        self::assertEquals("domain.some", $this->resp->getDomain());
    }

    public function testGetText()
    {
        self::assertEquals("Test content", $this->resp->getText());
    }

    public function testGetWhoisHost()
    {
        self::assertEquals("whois.host.abc", $this->resp->getWhoisHost());
    }
}