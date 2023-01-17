<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Asn;

trait AsnResponseDeprected
{
    /**
     * @deprecated will be removed in v4.2
     * @return string
     */
    public function getQuery()
    {
        return $this->query;
    }

    /**
     * @deprecated will be removed in v4.2
     * @return string
     */
    public function getText()
    {
        return $this->text;
    }

    /**
     * @deprecated will be removed in v4.2
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * @deprecated will be removed in v4.2
     * @return string
     */
    public function getAsn()
    {
        return $this->asn;
    }
}