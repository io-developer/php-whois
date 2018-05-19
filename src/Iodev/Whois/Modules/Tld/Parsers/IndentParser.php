<?php

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\ParserHelper;

class IndentParser extends BlockParser
{
    /**
     * @param string $line
     * @return bool
     */
    public static function validateLine($line)
    {
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
}
