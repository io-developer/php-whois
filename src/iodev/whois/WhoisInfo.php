<?php

namespace iodev\whois;

/**
 * @author Sergey Sedyshev
 */
class WhoisInfo
{
    /** @var WhoisResponse */
    public $response;
    
    /** @var string */
    public $domainName = "";
    
    /** @var string */
    public $domainNameUnicode = "";
    
    /** @var string */
    public $whoisServer = "";
    
    /** @var string[] */
    public $nameServers = [];
    
    /** @var int */
    public $creationDate = 0;
    
    /** @var int */
    public $expirationDate = 0;
    
    /** @var string[] */
    public $states = [];
    
    /** @var string */
    public $owner = "";
    
    /** @var string */
    public $registrar = "";
}
