<?php

namespace Iodev\Whois\Modules\Asn;

use InvalidArgumentException;

/**
 * Immutable data object
 */
class AsnRouteInfo
{
    /**
     * @param array $data
     * @throws InvalidArgumentException
     */
    public function __construct($data = [])
    {
        if (!is_array($data)) {
            throw new InvalidArgumentException("Data must be an array");
        }
        $this->data = $data;
    }

    /** @var array */
    private $data;

    /**
     * @return string
     */
    public function getRoute()
    {
        return $this->get("route", "");
    }

    /**
     * @return string
     */
    public function getRoute6()
    {
        return $this->get("route6", "");
    }

    /**
     * @return string
     */
    public function getDescr()
    {
        return $this->get("descr", "");
    }

    /**
     * @return string
     */
    public function getOrigin()
    {
        return $this->get("origin", "");
    }

    /**
     * @return string
     */
    public function getMntBy()
    {
        return $this->get("mnt-by", "");
    }

    /**
     * @return string
     */
    public function getChanged()
    {
        return $this->get("changed", "");
    }

    /**
     * @return string
     */
    public function getSource()
    {
        return $this->get("source", "");
    }

    /**
     * @param $key
     * @param mixed $default
     * @return mixed
     */
    public function get($key, $default = "")
    {
        return $this->data[$key] ?? $default;
    }

    /**
     * @return array
     */
    public function getData(): array
    {
        return $this->data;
    }
}