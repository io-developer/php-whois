<?php

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\DataObject;

/**
 * @property string $query
 * @property string $text
 * @property string $host
 * @property string $asn
 */
class AsnResponse extends DataObject
{
    use AsnResponseDeprected;

    /** @var string */
    protected $dataDefault = [
        'query' => '',
        'text' => '',
        'host' => '',
        'asn' => '',
    ];
}
