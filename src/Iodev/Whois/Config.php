<?php

namespace Iodev\Whois;

class Config
{
    /**
     * @param string $name
     * @return array
     */
    private static function loadJson($name)
    {
        $json = file_get_contents(__DIR__."/Configs/$name");
        return json_decode($json, true);
    }

    /**
     * @return array
     */
    public static function getServersData()
    {
        return self::loadJson("module.tld.servers.json");
    }

    /**
     * @param string $type
     * @return array
     */
    public static function getParserConfig($type = null)
    {
        if ($type == 'block') {
            return self::getBlockParserConfig();
        }
        if ($type == 'commonFlat') {
            return self::getCommonFlatParserConfig();
        }
        return self::getCommonParserConfig();
    }

    /**
     * @return array
     */
    private static function getBlockParserConfig()
    {
        return self::loadJson("module.tld.parsers.block.json");
    }

    /**
     * @return array
     */
    private static function getCommonFlatParserConfig()
    {
        $cfg = self::getCommonParserConfig();
        $cfg['isFlat'] = true;
        return $cfg;
    }

    /**
     * @return array
     */
    private static function getCommonParserConfig()
    {
        return self::loadJson("module.tld.parsers.common.json");
    }
}