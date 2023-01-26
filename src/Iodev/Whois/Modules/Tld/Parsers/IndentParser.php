<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Selection\GroupFilter;
use Iodev\Whois\Modules\Tld\TldParser;

class IndentParser extends BlockParser
{
    /** @var bool */
    protected $isAutofix = false;

    /** @var array */
    protected $secondaryStatesSubsets = [];

    public function getType(): string
    {
        return $this->isAutofix ? TldParser::INDENT_AUTOFIX : TldParser::INDENT;
    }

    /**
     * @param string[] $commentChars
     */
    public static function validateLine(string $line, array $commentChars = ['%']): bool
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

    public static function validateStopline(string $line): bool
    {
        return trim($line) != '--';
    }

    public static function validateBlock(array $block): bool
    {
        foreach ($block as $line) {
            $clean = preg_replace('~\w+://[-\w/\.#@?&:=%]+|\d\d:\d\d:\d\d~ui', '', $line);
            if (strpos($clean, ':') !== false) {
                return true;
            }
        }
        return false;
    }

    public static function biasIndent(string $line): int
    {
        $trimmed = rtrim($line);
        $len = strlen($trimmed);
        return ($len > 0 && $trimmed[$len - 1] == ':') ? -1 : 0;
    }

    protected function groupsFromText(string $text): array
    {
        $groups = [];
        $lines = $this->parserTool->splitLines($text);
        if ($this->isAutofix) {
            $lines = $this->parserTool->autofixTldLines($lines);
            $lines = $this->parserTool->removeInnerEmpties($lines, [__CLASS__, 'biasIndent']);
        }
        $lines = array_filter($lines, [__CLASS__, 'validateLine']);
        $blocks = $this->parserTool->linesToSpacedBlocks($lines, [__CLASS__, 'validateStopline']);
        //$blocks = array_filter($blocks, [__CLASS__, 'validateBlock']);
        foreach ($blocks as $block) {
            $nodes = $this->parserTool->blockToIndentedNodes($block, [__CLASS__, 'biasIndent'], 2);
            $dict = $this->parserTool->nodesToDict($nodes);
            $groups[] = $this->parserTool->dictToGroup($dict, $this->headerKey);
        }
        $groups = $this->parserTool->joinParentlessGroups($groups);
        return $groups;
    }

    protected function parseStates(GroupFilter $rootFilter, GroupFilter $primaryFilter): array
    {
        return $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->secondaryStatesSubsets)
            ->toSelector()
            ->selectItems(parent::parseStates($rootFilter, $primaryFilter))
            ->selectKeys($this->statesKeys)
            ->transform(fn($items) => $this->transformItemsIntoStates($items))
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll();
    }
}
