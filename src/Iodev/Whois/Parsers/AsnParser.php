<?php


namespace Iodev\Whois\Parsers;


use Iodev\Whois\AsnResponse;
use Iodev\Whois\RouteInfo;

class AsnParser
{
    private $routeKeys = [
        'route' => 'setRoute',
        'route6' => 'setRoute6',
        'descr' => 'setDescr',
        'origin' => 'setOrigin',
        'mnt-by' => 'setMntBy',
        'changed' => 'setChanged',
        'source' => 'setSource',
    ];

    /**
     * @param AsnResponse $asnResponse
     * @return RouteInfo[]
     */
    public function parseResponse(AsnResponse $asnResponse)
    {
        $separator = "\r\n";
        $line = strtok($asnResponse->getText(), $separator);

        $routes = [];

        $currentInfo = null;
        while ($line !== false) {
            foreach ($this->routeKeys as $key => $setter) {
                if (strpos($line, "$key:") === 0) {
                    if ($key === 'route' || $key == 'route6') {
                        $currentInfo = new RouteInfo();
                        $routes[] = $currentInfo;
                    }
                    if ($currentInfo) {
                        $value = trim(str_replace("$key:", '', $line));
                        $currentInfo->$setter($value);
                    }

                    break;
                }
            }

            $line = strtok($separator);
        }

        return $routes;
    }
}
