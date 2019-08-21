<?php

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\DataObject;

/**
 * @property string domain
 */
class TldResponse extends DataObject
{
    /** @var string */
    protected $dataDefault = [
        'query' => '',
        'text' => '',
        'host' => '',
        'domain' => '',
    ];
}
