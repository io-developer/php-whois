<?php

namespace Iodev\Whois;

use Iodev\Whois\Modules\ModuleType;

class ResponseTest extends \PHPUnit_Framework_TestCase
{
    /** @var Response */
    private $resp;

    public function setUp()
    {
        $this->resp = new Response(ModuleType::TLD, "domain.some", "Test content", "whois.host.abc");
    }


    public function testGetTarget()
    {
        self::assertEquals("domain.some", $this->resp->getTarget());
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