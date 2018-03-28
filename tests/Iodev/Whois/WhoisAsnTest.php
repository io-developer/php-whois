<?php


namespace Iodev\Whois;


use Iodev\Whois\Parsers\CommonParser;

class WhoisAsnTest extends \PHPUnit_Framework_TestCase
{
    private static function whoisFrom($filename)
    {
        $dataList = array_merge(Config::getServersData(), []);
        $p = new ServerProvider(Server::fromDataList($dataList));
        $l = new \FakeSocketLoader();
        $l->text = \TestData::loadContent($filename);
        $w = new Whois($p, $l);
        return $w;
    }

    /**
     * @dataProvider asns
     */
    public function testLoadAsnInfo($asn, $count)
    {
        $whois = self::whoisFrom("../asn_data_files/$asn.txt");

        $routes = $whois->loadAsnInfo(new Server('fake', 'fake.com', false, new CommonParser()), 'AS32934');

        $this->assertInternalType('array', $routes);
        $this->assertCount($count, $routes);

        /** @var RouteInfo $route */
        foreach ($routes as $route) {
            $this->assertInstanceOf('Iodev\Whois\RouteInfo', $route);
            $this->assertNotNull($route->getRoute() ?: $route->getRoute6());
        }
    }

    public function asns() {
        return [
            ['AS32934', 308],
            ['AS62041', 7],
        ];
    }

}
