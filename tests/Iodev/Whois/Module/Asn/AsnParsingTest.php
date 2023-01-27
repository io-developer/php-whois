<?php

declare(strict_types=1);

namespace Iodev\Whois\Module\Asn;

use InvalidArgumentException;
use Iodev\Whois\BaseTestCase;
use Iodev\Whois\Whois;

class AsnParsingTest extends BaseTestCase
{
    protected AsnModule $asnModule;

    protected function onConstructed()
    {
        $this->asnModule = $this->whois->getAsnModule();
    }

    protected function loadContent(string $filename): mixed
    {
        $file = __DIR__ . '/parsing_data/' . $filename;
        if (!file_exists($file)) {
            throw new InvalidArgumentException("File '$file' not found");
        }
        return file_get_contents($file);
    }

    public function getLoadAsnInfoData(): array
    {
        return [
            [ "AS32934", "AS32934/whois.ripe.net.txt", null ],
            [ "AS32934", "AS32934/whois.radb.net.txt", "AS32934/whois.radb.net.json" ],

            [ "AS62041", "AS62041/whois.ripe.net.txt", "AS62041/whois.ripe.net.json" ],
            [ "AS62041", "AS62041/whois.radb.net.txt", "AS62041/whois.radb.net.json" ],
        ];
    }

    /**
     * @dataProvider getLoadAsnInfoData
     */
    public function testLoadAsnInfo(string $asn, string $srcTextFilename, ?string $expectedJsonFilename): void
    {
        $this->loader->text = $this->loadContent($srcTextFilename);
        
        $info = $this->asnModule->loadAsnInfo($asn);

        if (empty($expectedJsonFilename)) {
            self::assertNull($info, "Loaded info should be null for empty response ($srcTextFilename)");
            return;
        }

        $expected = json_decode(self::loadContent($expectedJsonFilename), true);
        self::assertNotEmpty($expected, "Failed to load/parse expected json");

        self::assertNotNull($info, "Loaded info should not be null ($srcTextFilename)");

        self::assertEquals(
            $expected["asn"],
            $info->asn,
            "ASN mismatch ($srcTextFilename)"
        );

        return;

        $actualRoutes = $info->routes;
        $expectedRoutes = $expected['routes'];

        self::assertEquals(
            count($expectedRoutes),
            count($actualRoutes),
            "Routes count mismatch ($srcTextFilename)"
        );

        foreach ($actualRoutes as $index => $actualRoute) {
            $expectedRoute = $expectedRoutes[$index];
            self::assertEquals(
                $expectedRoute['route'],
                $actualRoute->route,
                "Route ($index) 'route' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute['route6'],
                $actualRoute->route6,
                "Route ($index) 'route6' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute['descr'],
                $actualRoute->descr,
                "Route ($index) 'descr' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute['origin'],
                $actualRoute->origin,
                "Route ($index) 'origin' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute['mntBy'],
                $actualRoute->mntBy,
                "Route ($index) 'mntBy' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute['changed'],
                $actualRoute->changed,
                "Route ($index) 'changed' mismatch ($srcTextFilename)"
            );
            self::assertEquals(
                $expectedRoute['source'],
                $actualRoute->source,
                "Route ($index) 'source' mismatch ($srcTextFilename)"
            );
        }
    }
}