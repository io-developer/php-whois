<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\GroupFilter;
use Iodev\Whois\Helpers\ParserHelper;
use Iodev\Whois\Modules\Tld\TldParser;

class IndentParser extends BlockParser
{
    /** @var array */
    protected $secondaryStatesSubsets = [];

    /**
     * @return string
     */
    public function getType()
    {
        return TldParser::INDENT;
    }

    /**
     * @param string $line
     * @param string[] $commentChars
     * @return bool
     */
    public static function validateLine($line, $commentChars = ['%'])
    {
        if ($line && in_array($line[0], $commentChars)) {
            return false;
        }
        $trimmed = trim($line);
        if (strlen($line) == strlen($trimmed)) {
            return !preg_match('~^\*.*\*$~ui', $trimmed);
        }
        return true;
    }

    /**
     * @param string $line
     * @return bool
     */
    public static function validateStopline($line)
    {
        return trim($line) != '--';
    }

    /**
     * @param array $block
     * @return bool
     */
    public static function validateBlock($block)
    {
        foreach ($block as $line) {
            $clean = preg_replace('~\w+://[-\w/\.#@?&:=%]+|\d\d:\d\d:\d\d~ui', '', $line);
            if (strpos($clean, ':') !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $line
     * @return int
     */
    public static function biasIndent($line)
    {
        $trimmed = rtrim($line);
        return ($trimmed[strlen($trimmed) - 1] == ':') ? -1 : 0;
    }

    /**
     * @param string $text
     * @return array
     */
    protected function groupsFromText($text)
    {
        $groups = [];
        $lines = ParserHelper::splitLines($text);
        $lines = array_filter($lines, [__CLASS__, 'validateLine']);
        $blocks = ParserHelper::linesToSpacedBlocks($lines, [__CLASS__, 'validateStopline']);
        //$blocks = array_filter($blocks, [__CLASS__, 'validateBlock']);
        foreach ($blocks as $block) {
            $nodes = ParserHelper::blockToIndentedNodes($block, [__CLASS__, 'biasIndent'], 2);
            $dict = ParserHelper::nodesToDict($nodes);
            $groups[] = ParserHelper::dictToGroup($dict, $this->headerKey);
        }
        return $groups;
    }

    /**
     * @param GroupFilter $rootFilter
     * @param GroupFilter $primaryFilter
     * @return array
     */
    protected function parseStates(GroupFilter $rootFilter, GroupFilter $primaryFilter)
    {
        return $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->secondaryStatesSubsets)
            ->toSelector()
            ->selectItems(parent::parseStates($rootFilter, $primaryFilter))
            ->selectKeys($this->statesKeys)
            ->mapStates()
            ->removeDuplicates()
            ->getAll();
    }
}
