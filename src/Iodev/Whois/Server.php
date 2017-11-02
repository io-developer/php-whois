<?php

namespace Iodev\Whois;

use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Parsers\CommonParser;
use Iodev\Whois\Parsers\IParser;

class Server
{
    /**
     * @param array $data
     * @param IParser|string $defaultParser
     * @return Server
     */
    public static function fromData($data, $defaultParser = '\Iodev\Whois\Parsers\CommonParser')
    {
        return new Server(
            $data['zone'],
            !empty($data['centralized']),
            $data['host'],
            isset($data['parser']) ? $data['parser'] : $defaultParser
        );
    }

    /**
     * @param array $dataList
     * @param IParser|string $defaultParser
     * @return Server[]
     */
    public static function fromDataList($dataList, $defaultParser = null)
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
     * @param bool $centralized
     * @param string $host
     * @param IParser|string $parserOrClass
     */
    public function __construct($zone, $centralized, $host, $parserOrClass)
    {
        $this->zone = strval($zone);
        $this->centralized = (bool)$centralized;
        $this->host = strval($host);

        if ($parserOrClass instanceof IParser) {
            $this->parser = $parserOrClass;
        } else {
            $this->parserClass = (string)$parserOrClass;
        }
    }

    /** @var string */
    private $zone;

    /** @var bool */
    private $centralized;

    /** @var string */
    private $host;
    
    /** @var IParser */
    private $parser;

    /** @var string */
    private $parserClass;

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
        if (!$this->parser) {
            $class = $this->parserClass;
            $this->parser = new $class();
        }
        return $this->parser;
    }
}
