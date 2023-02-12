<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Tool;

use Iodev\Whois\Module\Tld\NewDto\SingleLookupResponse;

class MostValuableLookupResolver
{
    public function resolveSingleTree(SingleLookupResponse $root): SingleLookupResponse
    {
        $variants = [$root];
        foreach ($root->getAltResponses() as $alt) {
            $variants[] = $this->resolveSingleTree($alt);
        }
        $child = $root->getChildResponse();
        if ($child !== null) {
            $variants[] = $this->resolveSingleTree($child);
        }
        $next = $root->getNextResponse();
        if ($next !== null) {
            $variants[] = $this->resolveSingleTree($next);
        }

        return $this->resolveSingleVariants($variants);
    }

    /**
     * @param SingleLookupResponse[] $variants
     */
    public function resolveSingleVariants(array $variants): ?SingleLookupResponse
    {
        if (count($variants) === 0) {
            return null;
        }
        usort($variants, function(SingleLookupResponse $a, SingleLookupResponse $b) {
            $aScore = $a->isValuable() ? $a->getLookupInfoScore() : -1;
            $bScore = $b->isValuable() ? $b->getLookupInfoScore() : -1;
            return $aScore <=> $bScore;
        });
        return $variants[0];
    }
}
