<?php

namespace iodev\whois;

/**
 * @author Sergey Sedyshev
 */
interface IWhoisInfoParser
{
    /**
     * @param WhoisResponse $response
     * @return WhoisInfo
     */
    function fromResponse( WhoisResponse $response );
}
