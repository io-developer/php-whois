<?php

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Response;

/**
 * @property string domain
 */
class DomainResponse extends Response
{
    public function __construct(array $data)
    {
        parent::__construct($data);
        $this->dataDefault = array_merge($this->dataDefault, [
            'domain' => '',
        ]);
    }
}
