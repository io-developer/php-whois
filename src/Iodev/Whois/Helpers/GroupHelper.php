<?php

namespace Iodev\Whois\Helpers;

class GroupHelper
{
    /**
     * @param array $group
     * @param bool $keysOnly
     * @return array
     */
    public static function toLowerCase($group, $keysOnly = false)
    {
        return $keysOnly
            ? self::mapRecursiveKeys($group, 'mb_strtolower')
            : self::mapRecursive($group, 'mb_strtolower');
    }

    /**
     * @param array $group
     * @param callable $callback
     * @return array
     */
    public static function mapRecursive($group, $callback) {
        $out = [];
        array_walk($group, function($val, $key) use (&$out, $callback) {
            $out[$callback($key)] = is_array($val) ? self::mapRecursive($val, $callback) : $callback($val);
        });
        return $out;
    }

    /**
     * @param array $group
     * @param callable $callback
     * @return array
     */
    public static function mapRecursiveKeys($group, $callback) {
        $out = [];
        array_walk($group, function($val, $key) use (&$out, $callback) {
            $out[$callback($key)] = is_array($val) ? self::mapRecursiveKeys($val, $callback) : $val;
        });
        return $out;
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @param bool $ignoreCase
     * @return string
     */
    public static function matchFirst($group, $keys, $ignoreCase = true)
    {
        if (empty($group)) {
            return "";
        }
        if ($ignoreCase) {
            $group = self::toLowerCase($group, true);
        }
        foreach ($keys as $k) {
            $k = $ignoreCase ? mb_strtolower($k) : $k;
            if (isset($group[$k])) {
                return $group[$k];
            }
        }
        return "";
    }

    /**
     * @param array $groups
     * @param string[] $keys
     * @param bool $ignoreCase
     * @return string
     */
    public static function matchFirstIn($groups, $keys, $ignoreCase = true)
    {
        foreach ($groups as $group) {
            $v = self::matchFirst($group, $keys, $ignoreCase);
            if (!empty($v)) {
                return $v;
            }
        }
        return "";
    }

    /**
     * @param array $groups
     * @param array $subsets
     * @param bool $ignoreCase
     * @return array|null
     */
    public static function findGroupHasSubsetOf($groups, $subsets, $ignoreCase = true)
    {
        $subsets = $ignoreCase ? self::toLowerCase($subsets) : $subsets;
        foreach ($groups as $group) {
            $g = $ignoreCase ? self::toLowerCase($group) : $group;
            if (self::hasSubsetOf($g, $subsets)) {
                return $group;
            }
        }
        return null;
    }

    /**
     * @param array $group
     * @param array $subsets
     * @return bool
     */
    public static function hasSubsetOf($group, $subsets)
    {
        foreach ($subsets as $subset) {
            if (self::hasSubset($group, $subset)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array $group
     * @param array $subset
     * @return bool
     */
    public static function hasSubset($group, $subset)
    {
        foreach ($subset as $k => $v) {
            if (!isset($group[$k])) {
                return false;
            }
            if (empty($v)) {
                continue;
            }
            if (is_array($group[$k])) {
                foreach ($group[$k] as $sub) {
                    if (strval($sub) == strval($v)) {
                        $found = true;
                    }
                }
            } else {
                $found = (strval($group[$k]) == strval($v));
            }
            if (empty($found)) {
                 return false;
            }
        }
        return true;
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
        $servers = self::getAsciiServers($group, $keys);
        return empty($servers) ? "" : $servers[0];
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
            $s = trim(preg_replace('~\[.*?\]~ui', '', DomainHelper::toAscii($raw)));
            if (!empty($s)) {
                $servers[] = $s;
            }
        }
        return $servers;
    }

    /**
     * @param array $group
     * @param string[] $keys
     * @param array $keysGroups
     * @return string[]
     */
    public static function getAsciiServersComplex($group, $keys, $keysGroups = null)
    {
        $servers = self::getAsciiServers($group, $keys);
        if (!empty($servers) || empty($keysGroups)) {
            return $servers;
        }
        foreach ($keysGroups as $keysGroup) {
            foreach ($keysGroup as $key) {
                $servers = array_merge($servers, self::getAsciiServers($group, [ $key ]));
            }
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
