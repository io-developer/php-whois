<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Parser;

use Iodev\Whois\Module\Tld\TldInfoRankCalculator;
use Iodev\Whois\Selection\GroupFilter;
use Iodev\Whois\Module\Tld\TldParser;
use Iodev\Whois\Tool\DateTool;
use Iodev\Whois\Tool\DomainTool;
use Iodev\Whois\Tool\ParserTool;

class IndentParser extends BlockParser
{
    public function __construct(
        IndentParserOpts $opts,
        TldInfoRankCalculator $isnfoRankCalculator,
        ParserTool $parserTool,
        DomainTool $domainTool,
        DateTool $dateTool,
    ) {
        parent::__construct(
            $opts,
            $isnfoRankCalculator,
            $parserTool,
            $domainTool,
            $dateTool
        );
    }

    public function getType(): string
    {
        return $this->getOpts()->isAutofix ? TldParser::INDENT_AUTOFIX : TldParser::INDENT;
    }

    public function getOpts(): IndentParserOpts
    {
        return $this->opts;
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
        if ($this->getOpts()->isAutofix) {
            $lines = $this->parserTool->autofixTldLines($lines);
            $lines = $this->parserTool->removeInnerEmpties($lines, [__CLASS__, 'biasIndent']);
        }
        $lines = array_filter($lines, [__CLASS__, 'validateLine']);
        $blocks = $this->parserTool->linesToSpacedBlocks($lines, [__CLASS__, 'validateStopline']);
        //$blocks = array_filter($blocks, [__CLASS__, 'validateBlock']);
        foreach ($blocks as $block) {
            $nodes = $this->parserTool->blockToIndentedNodes($block, [__CLASS__, 'biasIndent'], 2);
            $dict = $this->parserTool->nodesToDict($nodes);
            $groups[] = $this->parserTool->dictToGroup($dict, $this->getOpts()->headerKey);
        }
        $groups = $this->parserTool->joinParentlessGroups($groups);
        return $groups;
    }

    protected function parseStates(GroupFilter $rootFilter, GroupFilter $primaryFilter): array
    {
        return $rootFilter->cloneMe()
            ->useMatchFirstOnly(true)
            ->filterHasSubsetOf($this->getOpts()->secondaryStatesSubsets)
            ->toSelector()
            ->selectItems(parent::parseStates($rootFilter, $primaryFilter))
            ->selectKeys($this->getOpts()->statesKeys)
            ->transform(fn($items) => $this->transformItemsIntoStates($items))
            ->removeEmpty()
            ->removeDuplicates()
            ->getAll()
        ;
    }
}
