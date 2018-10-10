<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Modules\Tld\DomainResponse;
use Iodev\Whois\Modules\Tld\TldParser;

class AutoParser extends TldParser
{
    public function __construct()
    {
        $this->parsers = [
            TldParser::create(TldParser::COMMON),
            TldParser::create(TldParser::COMMON_FLAT),
            TldParser::create(TldParser::BLOCK),
            TldParser::create(TldParser::INDENT),
        ];
    }

    /** @var TldParser[] */
    private $parsers = [];

    /**
     * @return string
     */
    public function getType()
    {
        return TldParser::AUTO;
    }

    /**
     * @param array $cfg
     * @return $this
     */
    public function setConfig($cfg)
    {
        return $this;
    }

    /**
     * @param DomainResponse $response
     * @return DomainInfo
     */
    public function parseResponse(DomainResponse $response)
    {
        $items = [];
        foreach ($this->parsers as $parser) {
            $info = $parser->parseResponse($response);
            if ($info) {
                $items[] = $info;
            }
        }
        if (count($items) > 1) {
            usort($items, function(DomainInfo $a, DomainInfo $b) {
                return $b->calcValuation() - $a->calcValuation();
            });
        }
        return empty($items) ? null : reset($items);
    }
}
