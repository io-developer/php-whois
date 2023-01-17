<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

use InvalidArgumentException;
use Iodev\Whois\DataObject;

/**
 * @property string $route
 * @property string $route6
 * @property string $descr
 * @property string $origin
 * @property string $mntBy
 * @property string $changed
 * @property string $source
 */
class AsnRouteInfo extends DataObject
{
    use AsnRouteInfoDeprecated;

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
}
