<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Whois;

class QueryBuilder
{
    protected string $format = '%s';
    protected string $queryText = '';
    protected bool $optionStrict = false;

    public function setFormat(string $format): static
    {
        $this->format = $format;
        return $this;
    }

    public function setQueryText(string $queryText): static
    {
        $this->queryText = $queryText;
        return $this;
    }

    public function setOptionStrict(bool $strict): static
    {
        $this->optionStrict = $strict;
        return $this;
    }

    public function toString(): string
    {
        $query = sprintf($this->format, $this->queryText);
        if ($this->optionStrict && mb_substr($query, 0, 1) !== '=') {
            $query = "={$query}";
        }
        return $query;
    }
}
