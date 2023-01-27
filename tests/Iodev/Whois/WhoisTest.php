<?php

declare(strict_types=1);

namespace Iodev\Whois;

class WhoisTest extends BaseTestCase
{
    public function testConstruct()
    {
        $whois = $this->container->get(Whois::class);
        $this->assertInstanceOf(Whois::class, $whois);
    }
}
