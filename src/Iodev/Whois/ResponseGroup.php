<?php

namespace Iodev\Whois;

use Iodev\Whois\Helpers\ResponseHelper;

class ResponseGroup
{
    public function __construct($data = null)
    {
        $this->data = $data ? $data : [];
    }

    /** @var array */
    public $data;
    
    /**
     * @param array $lowerKeyDict
     * @return bool
     */
    public function getByKeyDict($lowerKeyDict)
    {
        return ResponseHelper::firstGroupMatch($this->data, array_keys($lowerKeyDict));
    }
}
