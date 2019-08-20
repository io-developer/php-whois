<?php

namespace Iodev\Whois\Modules\Asn;

use InvalidArgumentException;
use Iodev\Whois\DataObject;

/**
 * Immutable data object
 *
 * @property string route
 * @property string route6
 * @property string descr
 * @property string origin
 * @property string mntBy
 * @property string changed
 * @property string source
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

    /** @var array */
    protected $dataAlias = [
        "mntBy" => "mnt-by",
    ];

    /**
     * @return string
     */
    public function getRoute()
    {
        return $this->route;
    }

    /**
     * @return string
     */
    public function getRoute6()
    {
        return $this->route6;
    }

    /**
     * @return string
     */
    public function getDescr()
    {
        return $this->descr;
    }

    /**
     * @return string
     */
    public function getOrigin()
    {
        return $this->origin;
    }

    /**
     * @return string
     */
    public function getMntBy()
    {
        return $this->mntBy;
    }

    /**
     * @return string
     */
    public function getChanged()
    {
        return $this->changed;
    }

    /**
     * @return string
     */
    public function getSource()
    {
        return $this->source;
    }
}
