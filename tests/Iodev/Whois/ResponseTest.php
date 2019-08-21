<?php

namespace Iodev\Whois;

use PHPUnit\Framework\TestCase;

class ResponseTest extends TestCase
{
    /** @var Response */
    private $resp;

    public function setUp(): void
    {
        $this->resp = new Response([
            "query" => "domain.some",
            "text" => "Test content",
            "host" => "whois.host.abc",
        ]);
    }


    public function testGetQuery()
    {
        self::assertEquals("domain.some", $this->resp->query);
    }

    public function testGetText()
    {
        self::assertEquals("Test content", $this->resp->text);
    }

    public function testGetHost()
    {
        self::assertEquals("whois.host.abc", $this->resp->host);
    }
}