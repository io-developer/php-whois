<?php

namespace Iodev\Whois\Helpers;

class GroupHelper
{
    /**
     * @param string $responseText
     * @return array
     */
    public static function groupsFromResponseText($responseText)
    {
        $groups = [];
        $splits = preg_split('/([\s\t]*\r?\n){2,}/', $responseText);
        foreach ($splits as $split) {
            $group = [];
            preg_match_all('/^\s*(( *[\w-]+)+):[ \t]+(.*)$/mui', $split, $m);
            foreach ($m[1] as $index => $key) {
                $group = array_merge_recursive($group, [ $key => $m[3][$index] ]);
            }
            if (count($group) > 2) {
                $groups[] = $group;
            }
        }
        return $groups;
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @param bool $ignoreCase
     * @return string
     */
    public static function matchFirst($group, $keys, $ignoreCase = true)
    {
        $kDict = [];
        foreach ($keys as $k) {
            $k = $ignoreCase ? strtolower($k) : $k;
            $kDict[$k] = 1;
        }
        foreach ($group as $k => $v) {
            $k = $ignoreCase ? strtolower($k) : $k;
            if (isset($kDict[$k])) {
                return $v;
            }
        }
        return "";
    }

    /**
     * @param array $groups
     * @param string $domain
     * @param string[] $domainKeys
     * @return array
     */
    public static function findDomainGroup($groups, $domain, $domainKeys)
    {
        foreach ($groups as $group) {
            $foundDomain = self::getAsciiServer($group, $domainKeys);
            if ($foundDomain && DomainHelper::compareNames($foundDomain, $domain)) {
                return $group;
            }
        }
        return null;
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @return string
     */
    public static function getAsciiServer($group, $keys)
    {
        return DomainHelper::toAscii(self::matchFirst($group, $keys));
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @return string[]
     */
    public static function getAsciiServers($group, $keys)
    {
        $raws = self::matchFirst($group, $keys);
        $raws = !empty($raws) ? $raws : [];
        $raws = is_array($raws) ? $raws : [ $raws ];
        $servers = [];
        foreach ($raws as $raw) {
            $servers[] = DomainHelper::toAscii($raw);
        }
        return $servers;
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @return int
     */
    public static function getUnixtime($group, $keys)
    {
        return DateHelper::parseDate(self::matchFirst($group, $keys));
    }
}
