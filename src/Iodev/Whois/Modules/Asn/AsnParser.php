<?php

namespace Iodev\Whois\Modules\Asn;

class AsnParser
{
    /** @var string[]  */
    private $routeKeys = [
        'route',
        'route6',
        'descr',
        'origin',
        'mnt-by',
        'changed',
        'source',
    ];

    /**
     * @param AsnResponse $response
     * @return AsnInfo
     */
    public function parseResponse(AsnResponse $response)
    {
        return new AsnInfo($response, $response->getAsn(), $this->parseRoutes($response));
    }

    /**
     * @param AsnResponse $asnResponse
     * @return AsnRouteInfo[]
     */
    private function parseRoutes(AsnResponse $asnResponse)
    {
        $routes = [];
        $separator = "\r\n";
        $line = strtok($asnResponse->getText(), $separator);
        $data = null;
        while ($line !== false) {
            foreach ($this->routeKeys as $key) {
                if (strpos($line, "$key:") === 0) {
                    if ($key === 'route' || $key == 'route6') {
                        if (!empty($data)) {
                            $routes[] = new AsnRouteInfo($data);
                        }
                        $data = [];
                    }
                    if (isset($data)) {
                        $data[$key] = trim(str_replace("$key:", '', $line));
                    }
                    break;
                }
            }
            $line = strtok($separator);
        }
        if (!empty($data)) {
            $routes[] = new AsnRouteInfo($data);
        }
        return $routes;
    }
}
