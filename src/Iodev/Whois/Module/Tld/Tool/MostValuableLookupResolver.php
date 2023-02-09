<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Tld\Tool;

use Iodev\Whois\Module\Tld\NewDto\IntermediateLookupResponse;

class MostValuableLookupResolver
{
    public function resolveIntermediateTree(IntermediateLookupResponse $root): IntermediateLookupResponse
    {
        $variants = [$root];
        foreach ($root->getAltResponses() as $alt) {
            $variants[] = $this->resolveIntermediateTree($alt);
        }
        $child = $root->getChildResponse();
        if ($child !== null) {
            $variants[] = $this->resolveIntermediateTree($child);
        }
        $next = $root->getNextResponse();
        if ($next !== null) {
            $variants[] = $this->resolveIntermediateTree($next);
        }
        
        return $this->resolveIntermediateVariants($variants);
    }

    /**
     * @param IntermediateLookupResponse[] $variants
     */
    public function resolveIntermediateVariants(array $variants): ?IntermediateLookupResponse
    {
        if (count($variants) === 0) {
            return null;
        }
        usort($variants, function(IntermediateLookupResponse $a, IntermediateLookupResponse $b) {
            $aScore = $a->isValuable() ? $a->getLookupInfoScore() : -1;
            $bScore = $b->isValuable() ? $b->getLookupInfoScore() : -1;
            return $aScore <=> $bScore;
        });
        return $variants[0];
    }
}
