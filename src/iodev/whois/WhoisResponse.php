<?php

namespace iodev\whois;

/**
 * @author Sergey Sedyshev
 */
class WhoisResponse
{
    public function __construct( $requestedDomain="", $content="" )
    {
        $this->requestedDomain = $requestedDomain;
        $this->content = $content;
    }


    /** @var string */
    public $requestedDomain;
    
    /** @var string */
    public $content;
    
    /** @var WhoisResponseGroup[] */
    public $groups = [];
    
    
    /**
     * @return bool
     */
    public function isEmpty()
    {
        return (bool)(count($this->groups) < 1);
    }
}
