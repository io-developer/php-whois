<?php

class MyTest extends PHPUnit_Framework_TestCase
{
    public function testExample()
    {
        $whois = \Iodev\Whois\Whois::create();
        $this->assertNotEmpty($whois, "Error!");
    }
}
