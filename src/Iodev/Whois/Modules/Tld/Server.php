<?php

namespace Iodev\Whois\Modules\Tld;

use InvalidArgumentException;
use Iodev\Whois\Helpers\DomainHelper;

/**
 * Immutable data object
 */
class Server
{
    /**
     * @param array $data
     * @param Parser $defaultParser
     * @return Server
     */
    public static function fromData($data, Parser $defaultParser = null)
    {
        /* @var $parser Parser */
        $parser = $defaultParser;
        if (isset($data['parserClass'])) {
            $parser = Parser::createByClass($data['parserClass'], isset($data['parserType']) ? $data['parserType'] : null);
        } elseif (isset($data['parserType'])) {
            $parser = Parser::create($data['parserType']);
        }
        return new Server(
            isset($data['zone']) ? $data['zone'] : '',
            isset($data['host']) ? $data['host'] : '',
            !empty($data['centralized']),
            $parser ? $parser : Parser::create(),
            isset($data['queryFormat']) ? $data['queryFormat'] : null
        );
    }

    /**
     * @param array $dataList
     * @param Parser $defaultParser
     * @return Server[]
     */
    public static function fromDataList($dataList, Parser $defaultParser = null)
    {
        $defaultParser = $defaultParser ? $defaultParser : Parser::create();
        $servers = [];
        foreach ($dataList as $data) {
            $servers[] = self::fromData($data, $defaultParser);
        }
        return $servers;
    }

    /**
     * @param string $zone
     * @param string $host
     * @param bool $centralized
     * @param Parser $parser
     * @param string $queryFormat
     * @throws InvalidArgumentException
     */
    public function __construct($zone, $host, $centralized, Parser $parser, $queryFormat = null)
    {
        $this->zone = strval($zone);
        if (empty($this->zone)) {
            throw new InvalidArgumentException("Zone must be specified");
        }
        $this->host = strval($host);
        if (empty($this->host)) {
            throw new InvalidArgumentException("Host must be specified");
        }
        $this->centralized = (bool)$centralized;
        $this->parser = $parser;
        $this->queryFormat = !empty($queryFormat) ? strval($queryFormat) : "%s\r\n";
    }

    /** @var string */
    private $zone;

    /** @var bool */
    private $centralized;

    /** @var string */
    private $host;
    
    /** @var Parser */
    private $parser;

    /** @var string */
    private $queryFormat;

    /**
     * @return bool
     */
    public function isCentralized()
    {
        return (bool)$this->centralized;
    }

    /**
     * @param string $domain
     * @return bool
     */
    public function isDomainZone($domain)
    {
        return DomainHelper::belongsToZone($domain, $this->zone);
    }

    /**
     * @return string
     */
    public function getZone()
    {
        return $this->zone;
    }

    /**
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * @return Parser
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
     * @param string $domain
     * @param bool $strict
     * @return string
     */
    public function buildDomainQuery($domain, $strict = false)
    {
        $query = sprintf($this->queryFormat, $domain);
        return $strict ? "=$query" : $query;
    }
}
