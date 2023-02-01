<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parsing;

use Iodev\Whois\Module\Tld\Dto\LookupInfo;
use Iodev\Whois\Module\Tld\Dto\LookupResponse;
use Iodev\Whois\Module\Tld\Tool\LookupInfoScoreCalculator;

class AutoParser extends ParserInterface
{
    /** @var ParserInterface[] */
    protected $parsers = [];

    public function __construct(
        protected LookupInfoScoreCalculator $infoScoreCalculator,
    ) {}

    public function getType(): string
    {
        return ParserInterface::AUTO;
    }

    public function setConfig(array $cfg): static
    {
        return $this;
    }

    /**
     * @return ParserInterface[]
     */
    public function getParsers(): array
    {
        return $this->parsers;
    }

    /**
     * @param ParserInterface[] $parsers
     */
    public function setParsers(array $parsers): static
    {
        foreach ($parsers as $parser) {
            $this->addParser($parser);
        }
        return $this;
    }

    /**
     * @param ParserInterface $parser
     */
    public function addParser(ParserInterface $parser): static
    {
        $this->parsers[] = $parser;
        return $this;
    }

    public function parseResponse(LookupResponse $response): ?LookupInfo
    {
        $bestInfo = null;
        $bestRank = 0;
        foreach ($this->parsers as $parser) {
            $info = $parser->setOptions($this->options)->parseResponse($response);
            if (!$info) {
                continue;
            }
            $rank = $this->infoScoreCalculator->calcRank($info);
            if ($rank > $bestRank) {
                $bestRank = $rank;
                $bestInfo = $info;
            }
        }
        return $bestInfo;
    }
}
