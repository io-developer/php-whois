<?php

namespace Iodev\Whois;

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
        foreach ($this->data as $k => $v) {
            if (isset($lowerKeyDict[strtolower($k)])) {
                return $v;
            }
        }
        return false;
    }
}
