<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

class GroupFilter
{
    use GroupTrait;

    /**
     * @param string $domain
     * @param string[] $domainKeys
     * @return $this
     */
    public function filterIsDomain($domain, $domainKeys)
    {
        $groups = GroupHelper::findDomainGroups(
            $this->groups,
            $domain,
            $domainKeys,
            $this->matchFirstOnly
        );
        return $this->setGroups($groups);
    }

    /**
     * @param array $subsets
     * @return $this
     */
    public function filterHasSubsetOf($subsets)
    {
        $subsets = GroupHelper::renderSubsets($subsets, $this->subsetParams);
        $groups = GroupHelper::findGroupsHasSubsetOf(
            $this->groups,
            $subsets,
            $this->ignoreCase,
            $this->matchFirstOnly
        );
        return $this->setGroups($groups);
    }

    /**
     * @param array $subsetKeys
     * @return $this
     */
    public function filterHasSubsetKeyOf($subsetKeys)
    {
        $subsets = [];
        foreach ($subsetKeys as $k) {
            $subsets[] = [ $k => '' ];
        }
        $groups = GroupHelper::findGroupsHasSubsetOf(
            $this->groups,
            $subsets,
            $this->ignoreCase,
            $this->matchFirstOnly
        );
        return $this->setGroups($groups);
    }

    /**
     * @return $this
     */
    public function filterHasHeader()
    {
        $groups = GroupHelper::findGroupsHasSubsetOf(
            $this->groups,
            [[ $this->headerKey => '' ]],
            $this->ignoreCase,
            $this->matchFirstOnly
        );
        return $this->setGroups($groups);
    }

    /**
     * Replaces special empty values by NULL
     * @param array $extraDict
     * @return $this
     */
    public function handleEmpty($extraDict = [])
    {
        foreach ($this->groups as $index => &$group) {
            foreach ($group as $k => &$v) {
                if (is_array($v)) {
                    foreach ($v as &$subVal) {
                        if (is_string($subVal) && !empty($extraDict[(string)$subVal])) {
                            $subVal = null;
                        }
                    }
                } elseif (!empty($extraDict[(string)$v])) {
                    $v = null;
                }
            }
        }
        return $this;
    }

    /**
     * @return GroupSelector
     */
    public function toSelector()
    {
        return $this->createSelector()
            ->setGroups($this->groups)
            ->useIgnoreCase($this->ignoreCase)
            ->useMatchFirstOnly($this->matchFirstOnly)
            ->setHeaderKey($this->headerKey)
            ->setSubsetParams($this->subsetParams);
    }

    /**
     * @return GroupSelector
     */
    protected function createSelector(): GroupSelector
    {
        return new GroupSelector();
    }
}
