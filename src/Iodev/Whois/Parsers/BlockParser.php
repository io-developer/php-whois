<?php

namespace Iodev\Whois\Parsers;

use Iodev\Whois\DomainInfo;
use Iodev\Whois\Response;
use Iodev\Whois\Helpers\GroupHelper;

class BlockParser extends CommonParser
{
    const HEADER_KEY = ' header ';

    /**
     * @param Response $response
     * @return DomainInfo
     */
    public function parseResponse(Response $response)
    {
        return null;
        $groups = $this->groupsFromText($response->getText());
        var_dump($groups);
        return null;
    }

    /**
     * @param string $text
     * @return array
     */
    protected function groupFromText($text)
    {
        $group = [];
        $hasHeader = false;
        foreach (preg_split('~\r\n|[\r\n]~u', $text) as $line) {
            if ($hasHeader && ltrim($line, '%#*') !== $line) {
                continue;
            }
            $split = explode(':', ltrim($line, "%#*:;= \t\0\x0B"), 2);
            $k = isset($split[0]) ? trim($split[0]) : '';
            $v = isset($split[1]) ? trim($split[1]) : '';
            if (strlen($k) && strlen($v)) {
                $group = array_merge_recursive($group, [ $k => $v ]);
                continue;
            }
            $k = trim($k, "%#*:;=[] \t\0\x0B");
            if (strlen($k) && !$hasHeader) {
                $group = array_merge_recursive($group, [ self::HEADER_KEY => $k ]);
                $hasHeader = true;
            }
        }
        return $group;
    }
}
