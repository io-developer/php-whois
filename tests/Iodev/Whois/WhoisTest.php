<?php

namespace Iodev\Whois;

use Tools\FakeSocketLoader;

class WhoisTest extends \PHPUnit_Framework_TestCase
{
    /** @var Whois */
    private $whois;

    /** @var FakeSocketLoader */
    private $loader;


    public function setUp()
    {
        $this->loader = new FakeSocketLoader();
        $this->whois = new Whois($this->loader);
    }

    public function tearDown()
    {
    }


    public function testConstruct()
    {
        self::assertInstanceOf(Whois::class, new Whois(new FakeSocketLoader()));
    }
}
