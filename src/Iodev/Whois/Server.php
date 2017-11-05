<?php

namespace Iodev\Whois;

use InvalidArgumentException;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Parsers\CommonParser;
use Iodev\Whois\Parsers\IParser;

class Server
{
    /**
     * @param array $data
     * @param IParser $defaultParser
     * @return Server
     */
    public static function fromData($data, IParser $defaultParser = null)
    {
        $parser = $defaultParser;
        if (isset($data['parser'])) {
            $parserClass = $data['parser'];
            $parser = new $parserClass();
        }
        return new Server(
            isset($data['zone']) ? $data['zone'] : '',
            isset($data['host']) ? $data['host'] : '',
            !empty($data['centralized']),
            $parser ? $parser : new CommonParser()
        );
    }

    /**
     * @param array $dataList
     * @param IParser|string $defaultParser
     * @return Server[]
     */
    public static function fromDataList($dataList, IParser $defaultParser = null)
    {
        $defaultParser = $defaultParser ? $defaultParser : new CommonParser();
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
     * @param IParser $parser
     * @throws InvalidArgumentException
     */
    public function __construct($zone, $host, $centralized, IParser $parser)
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
    }

    /** @var string */
    private $zone;

    /** @var bool */
    private $centralized;

    /** @var string */
    private $host;
    
    /** @var IParser */
    private $parser;

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
     * @return IParser
     */
    public function getParser()
    {
        return $this->parser;
    }
}
