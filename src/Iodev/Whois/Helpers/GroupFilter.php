<?php

namespace Iodev\Whois\Helpers;

class GroupFilter
{
    /**
     * @return GroupFilter
     */
    public static function create($groups)
    {
        $m = new self();
        $m->setGroups($groups);
        return $m;
    }

    public function __construct()
    {
    }

    /** @var array */
    private $groups = [];

    /** @var array */
    private $subsetParams = [];

    /** @var array */
    private $domainKeys = [];

    /**
     * @return array
     */
    public function getFirstGroup()
    {
        return count($this->groups) ? $this->groups[0] : null;
    }

    /**
     * @return array
     */
    public function getGroups()
    {
        return $this->groups;
    }

    /**
     * @param array $groups
     * @return $this
     */
    public function setGroups($groups)
    {
        $this->groups = $groups;
        return $this;
    }

    /**
     * @param array $keys
     * @return $this
     */
    public function setDomainKeys($keys)
    {
        $this->domainKeys = $keys;
        return $this;
    }

    /**
     * @param array $params
     * @return $this
     */
    public function setSubsetParams($params)
    {
        $this->subsetParams = $params;
        return $this;
    }

    /**
     * @return $this
     */
    public function mergeGroups()
    {
        $finalGroup = [];
        foreach ($this->groups as $group) {
            $finalGroup = array_merge_recursive($finalGroup, $group);
        }
        $this->groups = [ $finalGroup ];
        return $this;
    }

    /**
     * @param string $domain
     * @param bool $matchFirst
     * @return $this
     */
    public function filterIsDomain($domain, $matchFirst = false)
    {
        $this->groups = GroupHelper::findDomainGroups($this->groups, $domain, $this->domainKeys, $matchFirst);
        return $this;
    }

    /**
     * @param array $subsets
     * @param bool $matchFirst
     * @return $this
     */
    public function filterHasSubsetOf($subsets, $matchFirst = false)
    {
        $subsets = GroupHelper::renderSubsets($subsets, $this->subsetParams);
        $this->groups = GroupHelper::findGroupsHasSubsetOf($this->groups, $subsets, true, $matchFirst);
        return $this;
    }

    /**
     * @param array $subsetKeys
     * @param bool $matchFirst
     * @return $this
     */
    public function filterHasSubsetKeyOf($subsetKeys, $matchFirst = false)
    {
        $subsets = [];
        foreach ($subsetKeys as $k) {
            $subsets[] = [ $k => '' ];
        }
        $this->groups = GroupHelper::findGroupsHasSubsetOf($this->groups, $subsets, true, $matchFirst);
        return $this;
    }
}
