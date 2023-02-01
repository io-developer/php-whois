<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Whois;

use Iodev\Whois\BaseTestCase;
use Iodev\Whois\Module\Tld\Parsing\TestCommonParser;

class QueryBuilderTest extends BaseTestCase
{
    private QueryBuilder $queryBuilder;

    protected function onConstructed()
    {
    }

    public function setUp(): void
    {
        $this->queryBuilder = new QueryBuilder();
    }

    public function testBuilQuery()
    {
        $query = $this->queryBuilder
            ->setFormat("prefix %s suffix\r\n")
            ->setQueryText('domain.com')
            ->toString()
        ;
        self::assertEquals("prefix domain.com suffix\r\n", $query);
    }

    public function testBuilQueryNoParam()
    {
        $query = $this->queryBuilder
            ->setFormat("prefix suffix\r\n")
            ->setQueryText('domain.com')
            ->toString()
        ;
        self::assertEquals("prefix suffix\r\n", $query);
    }

    public function testBuilQueryStrict()
    {
        $query = $this->queryBuilder
            ->setFormat("%s\r\n")
            ->setQueryText('domain.com')
            ->setOptionStrict(true)
            ->toString()
        ;
        self::assertEquals("=domain.com\r\n", $query);
    }

    public function testBuilQueryStrictDouble()
    {
        $query = $this->queryBuilder
            ->setFormat("%s\r\n")
            ->setQueryText('=domain.com')
            ->setOptionStrict(true)
            ->toString()
        ;
        self::assertEquals("=domain.com\r\n", $query);
    }
}
