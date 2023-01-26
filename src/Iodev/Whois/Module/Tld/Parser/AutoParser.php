<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parser;

use Iodev\Whois\Module\Tld\TldInfo;
use Iodev\Whois\Module\Tld\TldInfoRankCalculator;
use Iodev\Whois\Module\Tld\TldResponse;
use Iodev\Whois\Module\Tld\TldParser;

class AutoParser extends TldParser
{
    /** @var TldParser[] */
    protected $parsers = [];

    public function __construct(
        protected TldInfoRankCalculator $infoRankCalculator,
    ) {}

    public function getType(): string
    {
        return TldParser::AUTO;
    }

    public function setConfig(array $cfg): static
    {
        return $this;
    }

    /**
     * @return TldParser[]
     */
    public function getParsers(): array
    {
        return $this->parsers;
    }

    /**
     * @param TldParser[] $parsers
     */
    public function setParsers(array $parsers): static
    {
        foreach ($parsers as $parser) {
            $this->addParser($parser);
        }
        return $this;
    }

    /**
     * @param TldParser $parser
     */
    public function addParser(TldParser $parser): static
    {
        $this->parsers[] = $parser;
        return $this;
    }

    public function parseResponse(TldResponse $response): ?TldInfo
    {
        $bestInfo = null;
        $bestRank = 0;
        foreach ($this->parsers as $parser) {
            $info = $parser->setOptions($this->options)->parseResponse($response);
            if (!$info) {
                continue;
            }
            $rank = $this->infoRankCalculator->calcRank($info);
            if ($rank > $bestRank) {
                $bestRank = $rank;
                $bestInfo = $info;
            }
        }
        return $bestInfo;
    }
}
