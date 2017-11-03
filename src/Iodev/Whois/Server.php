<?php

namespace Iodev\Whois;

use InvalidArgumentException;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Parsers\CommonParser;
use Iodev\Whois\Parsers\IParser;
use RuntimeException;

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
            isset($data['zone']) ? $data['zone'] : '',
            isset($data['host']) ? $data['host'] : '',
            !empty($data['centralized']),
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
     * @param string $host
     * @param bool $centralized
     * @param IParser|string $parserOrClass
     * @throws InvalidArgumentException
     */
    public function __construct($zone, $host, $centralized, $parserOrClass)
    {
        $this->zone = strval($zone);
        $this->host = strval($host);
        $this->centralized = (bool)$centralized;

        if ($parserOrClass instanceof IParser) {
            $this->parser = $parserOrClass;
        } elseif (is_string($parserOrClass)) {
            $this->parserClass = strval($parserOrClass);
        }

        if (empty($this->zone)) {
            throw new InvalidArgumentException("Zone must be specified");
        }
        if (empty($this->host)) {
            throw new InvalidArgumentException("Host must be specified");
        }
        if (empty($this->parser) && empty($this->parserClass)) {
            throw new InvalidArgumentException("Parser or parser class not specified ($parserOrClass)");
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
     * @throws RuntimeException  if parser class not valid
     */
    public function getParser()
    {
        if (!$this->parser) {
            $class = $this->parserClass;
            $this->parser = new $class();
            if (!($this->parser instanceof IParser)) {
                $this->parser = null;
                throw new RuntimeException("Parser class must implements IParser");
            }
        }
        return $this->parser;
    }
}
