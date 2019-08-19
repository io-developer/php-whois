<?php

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Config;
use Iodev\Whois\WhoisFactory;

abstract class TldParser
{
    const AUTO = 'auto';
    const COMMON = 'common';
    const COMMON_FLAT = 'commonFlat';
    const BLOCK = 'block';
    const INDENT = 'indent';
    const INDENT_AUTOFIX = 'indentAutofix';

    /**
     * @param string $type
     * @return TldParser
     */
    public static function create($type = null)
    {
        return WhoisFactory::getInstance()->createTldParser($type);
    }

    /**
     * @var array
     */
    protected $options = [];

    /**
     * @return array
     */
    public function getOptions()
    {
        return $this->options;
    }

    /**
     * @param string $key
     * @param mixed $def
     * @return mixed
     */
    public function getOption($key, $def = null)
    {
        return array_key_exists($key, $this->options) ? $this->options[$key] : $def;
    }

    /**
     * @param array $options
     * @return $this
     */
    public function setOptions($options)
    {
        $this->options = is_array($options) ? $options : [];
        return $this;
    }

    /**
     * @return string
     */
    abstract public function getType();

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
