<?php

namespace Iodev\Whois\Modules\Asn;

use Iodev\Whois\Response;

/**
 * @property string asn
 */
class AsnResponse extends Response
{
    public function __construct(array $data)
    {
        parent::__construct($data);
        $this->dataDefault = array_merge($this->dataDefault, [
            'asn' => '',
        ]);
    }
}
