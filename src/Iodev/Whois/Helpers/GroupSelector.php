<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Tool\DomainTool;

class GroupSelector
{
    use GroupTrait;
    

    /** @var array */
    private array $items = [];


    public function __construct(
        protected DomainTool $domainTool,
    ) {}

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
     * First item
     * @param mixed $default
     * @return mixed
     */
    public function getFirstItem($default = null)
    {
        return empty($this->items) ? $default : reset($this->items);
    }

    /**
     * First non-array value
     * @param mixed $default
     * @return mixed
     */
    public function getFirst($default = null)
    {
        $first = $this->getFirstItem();
        while (is_array($first)) {
            $first = count($first) > 0 ? reset($first) : null;
        }
        return $first !== null ? $first : $default;
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
            $matches = GroupHelper::matchKeys($group, $keys, $this->matchFirstOnly);
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

    public function sort(int $flags = SORT_REGULAR): self
    {
        sort($this->items, $flags);
        return $this;
    }

    /**
     * @return $this
     */
    public function mapDomain()
    {
        foreach ($this->items as &$item) {
            if ($item && preg_match('~([-\pL\d]+\.)+[-\pL\d]+~ui', $item, $m)) {
                $ascii = $this->domainTool->toAscii($m[0]);
                $item = $this->domainTool->filterAscii($ascii);
            } else {
                $item = '';
            }
        }
        return $this;
    }

    /**
     * @return $this
     */
    public function mapAsciiServer()
    {
        foreach ($this->items as &$item) {
            $raw = is_string($item) ? trim($item, '.') : '';
            $ascii = $this->domainTool->toAscii($raw);
            $item = $this->domainTool->filterAscii($ascii);
            if ($item && !preg_match('~^([-\pL\d]+\.)+[-\pL\d]+$~ui', $item)) {
                if (!preg_match('~^[a-z\d]+-norid$~ui', $item)) {
                    $item = '';
                }
            }
        }
        return $this;
    }

    /**
     * @param bool $inverseMMDD
     * @return $this
     */
    public function mapUnixTime($inverseMMDD = false)
    {
        $this->items = array_map(function($item) use ($inverseMMDD) {
            return is_string($item) ? DateHelper::parseDate($item, $inverseMMDD) : 0;
        }, $this->items);
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
            foreach (ParserHelper::parseStates($item, $removeExtra) as $k => $state) {
                if (is_int($k) && is_string($state)) {
                    $states[] = $state;
                }
            }
        }
        $this->items = $states;
        return $this;
    }
}
