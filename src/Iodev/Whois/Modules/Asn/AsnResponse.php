<?php

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\DataObject;

/**
 * @property string asn
 */
class AsnResponse extends DataObject
{
    /** @var string */
    protected $dataDefault = [
        'query' => '',
        'text' => '',
        'host' => '',
        'asn' => '',
    ];
}
