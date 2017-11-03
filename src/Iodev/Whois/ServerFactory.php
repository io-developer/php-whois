<?php

namespace Iodev\Whois;

use Iodev\Whois\Parsers\IParser;

class ServerFactory
{
    /** @var array */
    private static $configs = null;

    /** @var IParser[] */
    private static $parserPool = [];

    /**
     * @return array
     */
    private static function getConfigs()
    {
        if (!isset(self::$configs)) {
            self::$configs = require __DIR__ . '/_servers.php';
        }
        return self::$configs;
    }

    /**
     * @return Server[]
     */
    public static function createAll()
    {
        $servers = [];
        foreach (self::getConfigs() as $conf) {
            $servers[] = self::createFromConfig($conf);
        }
        return $servers;
    }

    /**
     * @param string[] $zones
     * @return Server[]
     */
    public static function createSome($zones)
    {
        $hash = array_flip($zones);
        $servers = [];
        foreach (self::getConfigs() as $conf) {
            if (isset($hash[$conf["zone"]])) {
                $servers[] = self::createFromConfig($conf);
            }
        }
        return $servers;
    }

    /**
     * @param $conf
     * @return Server
     */
    public static function createFromConfig($conf)
    {
        $parserClass = isset($conf['parser']) ? $conf['parser'] : '\Iodev\Whois\Parsers\CommonParser';
        if (isset(self::$parserPool[$parserClass])) {
            $parser = self::$parserPool[$parserClass];
        } else {
            $parser = self::$parserPool[$parserClass] = new $parserClass();
        }
        return new Server($conf['zone'], $conf['host'], !empty($conf['centralized']), $parser);
    }
}
