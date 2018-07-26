<?php

namespace Iodev\Whois\Helpers;

class GroupSelector
{
    use GroupTrait;

    /**
     * @param array $groups
     * @return $this
     */
    public static function create($groups = [])
    {
        $m = new self();
        return $m->setGroups($groups);
    }

    /** @var array */
    private $items = [];

    /**
     * @return bool
     */
    public function isEmpty()
    {
        return empty($this->items);
    }

    /**
     * @return array
     */
    public function getAll()
    {
        return $this->items;
    }

    /**
     * @return mixed|null
     */
    public function getFirst()
    {
        return empty($this->items) ? null : reset($this->items);
    }

    /**
     * @return $this
     */
    public function clean()
    {
        $this->items = [];
        return $this;
    }

    /**
     * @param array $items
     * @return $this
     */
    public function selectItems($items)
    {
        $this->items = array_merge($this->items, $items);
        return $this;
    }

    /**
     * @param string[] $keys
     * @return $this
     */
    public function selectKeys($keys)
    {
        foreach ($this->groups as $group) {
            $matches = GroupHelper::match($group, $keys, $this->ignoreCase, $this->matchFirstOnly);
            foreach ($matches as $match) {
                if (is_array($match)) {
                    $this->items = array_merge($this->items, $match);
                } else {
                    $this->items[] = $match;
                }
            }
        }
        return $this;
    }

    /**
     * @param array $keyGroups
     * @return $this
     */
    public function selectKeyGroups($keyGroups)
    {
        foreach ($keyGroups as $keyGroup) {
            foreach ($keyGroup as $key) {
                $this->selectKeys([ $key ]);
            }
        }
        return $this;
    }

    /**
     * @return $this
     */
    public function removeEmpty()
    {
        $this->items = array_filter($this->items);
        return $this;
    }

    /**
     * @return $this
     */
    public function removeDuplicates()
    {
        $this->items = array_unique($this->items);
        return $this;
    }

    /**
     * @return $this
     */
    public function mapAsciiServer()
    {
        $this->items = array_map('\Iodev\Whois\Helpers\DomainHelper::toAscii', $this->items);
        return $this;
    }

    /**
     * @return $this
     */
    public function mapUnixTime()
    {
        $this->items = array_map('\Iodev\Whois\Helpers\DateHelper::parseDate', $this->items);
        return $this;
    }

    /**
     * @param bool $removeExtra
     * @return $this
     */
    public function mapStates($removeExtra = true)
    {
        $states = [];
        foreach ($this->items as $item) {
            $states = array_merge($states, ParserHelper::parseStates($item, $removeExtra));
        }
        $this->items = $states;
        return $this;
    }
}
