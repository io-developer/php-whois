<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Tool\DomainTool;

class GroupSelector
{
    use GroupTrait;
    

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
     */
    public function getFirstItem(mixed $default = null): mixed
    {
        return count($this->items) > 0 ? reset($this->items) : $default;
    }

    /**
     * First non-array value
     */
    public function getFirst(mixed $default = null): mixed
    {
        $first = $this->getFirstItem();
        while (is_array($first)) {
            $first = count($first) > 0 ? reset($first) : null;
        }
        return $first !== null ? $first : $default;
    }

    public function clean(): static
    {
        $this->items = [];
        return $this;
    }

    public function selectItems(array $items): static
    {
        $this->items = array_merge($this->items, $items);
        return $this;
    }

    /**
     * @param string[] $keys
     */
    public function selectKeys(array $keys): static
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

    public function selectKeyGroups(array $keyGroups): static
    {
        foreach ($keyGroups as $keyGroup) {
            foreach ($keyGroup as $key) {
                $this->selectKeys([ $key ]);
            }
        }
        return $this;
    }

    public function removeEmpty(): static
    {
        $this->items = array_filter($this->items);
        return $this;
    }

    public function removeDuplicates(): static
    {
        $this->items = array_unique($this->items);
        return $this;
    }

    public function sort(int $flags = SORT_REGULAR): static
    {
        sort($this->items, $flags);
        return $this;
    }

    public function mapDomain(): static
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

    public function mapAsciiServer(): static
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

    public function mapUnixTime(bool $inverseMMDD = false): static
    {
        $this->items = array_map(function($item) use ($inverseMMDD) {
            return is_string($item) ? DateHelper::parseDate($item, $inverseMMDD) : 0;
        }, $this->items);
        return $this;
    }

    public function mapStates(bool $removeExtra = true): static
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
