<?php

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\DataObject;

/**
 * @property string asn
 * @property AsnRouteInfo[] routes
 */
class AsnInfo extends DataObject
{
    use AsnInfoDeprecated;

    /**
     * @param AsnResponse $response
     * @param array $data
     */
    public function __construct(AsnResponse $response, array $data)
    {
        parent::__construct($data);
        $this->response = $response;
    }

    /** @var AsnResponse */
    protected $response;

    /** @var array */
    protected $dataDefault = [
        "asn" => "",
        "routes" => [],
    ];

    /**
     * @return AsnResponse
     */
    public function getResponse(): AsnResponse
    {
        return $this->response;
    }
}
