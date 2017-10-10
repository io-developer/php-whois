<?php

namespace Iodev\Whois;

class Info
{
    /** @var Response */
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


    public function getHash()
    {
        return md5(serialize([
            $this->domainName,
            $this->domainNameUnicode,
            $this->whoisServer,
            $this->nameServers,
            $this->creationDate,
            $this->expirationDate,
            $this->states,
            $this->owner,
            $this->registrar,
        ]));
    }
}
