<?php

namespace Iodev\Whois;

use InvalidArgumentException;
use Iodev\Whois\Helpers\DomainHelper;

class DomainInfo
{
    /**
     * @param array $data
     * @throws InvalidArgumentException
     */
    public function __construct($data)
    {
        foreach ($data as $field => $val) {
            if (property_exists($this, $field)) {
                $this->{$field} = $val;
            } else {
                throw new InvalidArgumentException("Unsupported data field '$field'");
            }
        }
    }

    /** @var Response */
    private $response;

    /** @var string */
    private $domainName = "";

    /** @var string */
    private $whoisServer = "";

    /** @var string[] */
    private $nameServers = [];

    /** @var int */
    private $creationDate = 0;

    /** @var int */
    private $expirationDate = 0;

    /** @var string[] */
    private $states = [];

    /** @var string */
    private $owner = "";

    /** @var string */
    private $registrar = "";


    /**
     * @return Response
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * @return string
     */
    public function getDomainName()
    {
        return $this->domainName;
    }

    /**
     * @return string
     */
    public function getDomainNameUnicode()
    {
        return DomainHelper::toUnicode($this->domainName);
    }

    /**
     * @return string
     */
    public function getWhoisServer()
    {
        return $this->whoisServer;
    }

    /**
     * @return string[]
     */
    public function getNameServers()
    {
        return $this->nameServers;
    }

    /**
     * @return int
     */
    public function getCreationDate()
    {
        return $this->creationDate;
    }

    /**
     * @return int
     */
    public function getExpirationDate()
    {
        return $this->expirationDate;
    }

    /**
     * @return string[]
     */
    public function getStates()
    {
        return $this->states;
    }

    /**
     * @return string
     */
    public function getOwner()
    {
        return $this->owner;
    }

    /**
     * @return string
     */
    public function getRegistrar()
    {
        return $this->registrar;
    }
}
