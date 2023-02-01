<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Whois;

use Iodev\Whois\BaseTestCase;
use Iodev\Whois\Module\Tld\Dto\WhoisServer;
use Iodev\Whois\Module\Tld\Parsing\TestCommonParser;
use Iodev\Whois\Tool\DomainTool;

class ServerMatcherTest extends BaseTestCase
{
    public const TLD = '.abc';

    private WhoisServer $server;
    private ServerMatcher $serverMatcher;

    protected function onConstructed()
    {
        $parser = $this->container->get(TestCommonParser::class);
        $this->server = (new WhoisServer())
            ->setTld(self::TLD)
            ->setHost('')
            ->setPriority(0)
            ->setCentralized(false)
            ->setParser($parser)
            ->setQueryFormat("%s\r\n")
        ;
    }

    public function setUp(): void
    {
        $this->serverMatcher = new ServerMatcher(
            $this->container->get(DomainTool::class),
        );
    }
    
    public function testIsDomainZoneValid()
    {
        $result = $this->serverMatcher->isDomainZone($this->server, 'some.abc');
        self::assertTrue($result);
    }

    public function testIsDomainZoneValidComplex()
    {
        $result = $this->serverMatcher->isDomainZone($this->server, 'some.foo.bar.abc');
        self::assertTrue($result);
    }

    public function testIsDomainZoneInvalid()
    {
        $result = $this->serverMatcher->isDomainZone($this->server, 'some.com');
        self::assertFalse($result);
    }

    public function testIsDomainZoneInvalidEnd()
    {
        $result = $this->serverMatcher->isDomainZone($this->server, 'some.bar');
        self::assertFalse($result);
    }
}
