<?php

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Config;

abstract class TldParser
{
    const COMMON = 'common';
    const COMMON_FLAT = 'commonFlat';
    const BLOCK = 'block';
    const INDENT = 'indent';

    /**
     * @param string $type
     * @return TldParser
     */
    public static function create($type = null)
    {
        $type = $type ? $type : self::COMMON;
        $d = [
            self::COMMON => '\Iodev\Whois\Modules\Tld\Parsers\CommonParser',
            self::COMMON_FLAT => '\Iodev\Whois\Modules\Tld\Parsers\CommonParser',
            self::BLOCK => '\Iodev\Whois\Modules\Tld\Parsers\BlockParser',
            self::INDENT => '\Iodev\Whois\Modules\Tld\Parsers\IndentParser',
        ];
        return self::createByClass($d[$type], $type);
    }

    /**
     * @param string $className
     * @param string $configType
     * @return TldParser
     */
    public static function createByClass($className, $configType = null)
    {
        $configType = empty($configType) ? self::COMMON : $configType;

        /* @var $p TldParser */
        $p = new $className();
        $p->setConfig(self::getConfigByType($configType));
        return $p;
    }

    /**
     * @param string $type
     * @return array
     */
    public static function getConfigByType($type)
    {
        if ($type == self::COMMON_FLAT) {
            $type = self::COMMON;
            $extra = ['isFlat' => true];
        }
        $config = Config::load("module.tld.parsers.$type");
        return empty($extra) ? $config : array_merge($config, $extra);
    }

    /**
     * @param array $cfg
     * @return $this
     */
    abstract public function setConfig($cfg);

    /**
     * @param DomainResponse $response
     * @return DomainInfo
     */
    abstract public function parseResponse(DomainResponse $response);
}
