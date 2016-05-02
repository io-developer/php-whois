<?php

namespace iodev\whois;

/**
 * @author Sergey Sedyshev
 */
class WhoisResponseGroup
{
    public function __construct( $data=null )
    {
        $this->data = $data ? $data : [];
    }
    
    
    /** @var array */
    public $data;
    
    
    /**
     * @param array $lowerKeyDict
     * @return bool
     */
    public function getByKeyDict( $lowerKeyDict )
    {
        foreach ($this->data as $k => $v) {
            if ($lowerKeyDict[strtolower($k)]) {
                return $v;
            }
        }
        return false;
    }
}
