<?php

namespace Iodev\Whois\Modules\Asn;

use InvalidArgumentException;

/**
 * Immutable data object
 */
class AsnServer
{
    /**
     * @param string $host
     * @param AsnParser $parser
     * @param string $queryFormat
     * @throws InvalidArgumentException
     */
    public function __construct($host, AsnParser $parser, $queryFormat = "-i origin %s\r\n")
    {
        $this->host = strval($host);
        if (empty($this->host)) {
            throw new InvalidArgumentException("Host must be specified");
        }
        $this->parser = $parser;
        $this->queryFormat = strval($queryFormat);
    }

    /** @var string */
    private $host;

    /** @var AsnParser */
    private $parser;

    /** @var string */
    private $queryFormat;

    /**
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * @return AsnParser
     */
    public function getParser()
    {
        return $this->parser;
    }

    /**
     * @return string
     */
    public function getQueryFormat()
    {
        return $this->queryFormat;
    }

    /**
     * @param string $asn
     * @return string
     */
    public function buildQuery($asn)
    {
        return sprintf($this->queryFormat, $asn);
    }
}
