<?php

namespace Iodev\Whois\Modules\Asn;

use InvalidArgumentException;
use Iodev\Whois\DataObject;

/**
 * Immutable data object
 */
class AsnRouteInfo extends DataObject
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
        parent::__construct($data);
    }

    /** @var array */
    protected $dataDefault = [
        "route" => "",
        "route6" => "",
        "descr" => "",
        "origin" => "",
        "mntBy" => "",
        "changed" => "",
        "source" => "",
    ];

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
}
