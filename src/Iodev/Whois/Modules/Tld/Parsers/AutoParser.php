<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Modules\Tld\DomainResponse;
use Iodev\Whois\Modules\Tld\TldParser;

class AutoParser extends TldParser
{
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
     * @return TldParser[]
     */
    public function getParsers()
    {
        return $this->parsers;
    }

    /**
     * @param TldParser[] $parsers
     * @return $this
     */
    public function setParsers(array $parsers)
    {
        foreach ($parsers as $parser) {
            $this->addParser($parser);
        }
        return $this;
    }

    /**
     * @param TldParser $parser
     * @return $this
     */
    public function addParser(TldParser $parser)
    {
        $this->parsers[] = $parser;
        return $this;
    }

    /**
     * @param DomainResponse $response
     * @return DomainInfo
     */
    public function parseResponse(DomainResponse $response)
    {
        $bestInfo = null;
        $bestVal = 0;
        foreach ($this->parsers as $parser) {
            $info = $parser->setOptions($this->options)->parseResponse($response);
            if (!$info) {
                continue;
            }
            $val = $info->calcValuation();
            if ($val > $bestVal) {
                $bestVal = $val;
                $bestInfo = $info;
            }
        }
        return $bestInfo;
    }
}
