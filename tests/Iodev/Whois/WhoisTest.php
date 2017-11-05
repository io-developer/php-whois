<?php

namespace Iodev\Whois;

use FakeSocketLoader;
use Iodev\Whois\Helpers\GroupHelper;
use Iodev\Whois\Loaders\SocketLoader;

class WhoisTest extends \PHPUnit_Framework_TestCase
{
    /** @var Whois */
    private $whois;

    /** @var ServerProvider */
    private $provider;

    /** @var FakeSocketLoader */
    private $loader;

    /**
     * @return Whois
     */
    private function getWhois()
    {
        $this->provider = new ServerProvider(Server::fromDataList(Config::getServersData()));
        $this->loader = new FakeSocketLoader();
        $this->whois = new Whois($this->provider, $this->loader);
        return $this->whois;
    }

    private function loadTestDataInfo($domain, $filename)
    {
        $w = $this->getWhois();
        $l = $this->loader;
        $l->text = \TestData::loadContent($filename);
        return $w->loadInfo($domain);
    }

    private static function sort($a)
    {
        sort($a);
        return $a;
    }


    public function testConstruct()
    {
        new Whois(new ServerProvider([]), new SocketLoader());
    }

    public function testGetServerProvider()
    {
        $w = $this->getWhois();
        self::assertSame($this->provider, $w->getServerProvider());
    }

    public function testGetLoader()
    {
        $w = $this->getWhois();
        self::assertSame($this->loader, $w->getLoader());
    }

    public function testLoadInfoRegistered()
    {
        $info = self::loadTestDataInfo("google.com", "google.com.txt");
        self::assertNotNull($info);
        self::assertInstanceOf('\Iodev\Whois\DomainInfo', $info);
    }

    public function testLoadInfoNotRegistered()
    {
        $info = $this->loadTestDataInfo("google.com", "notregistered.txt");
        self::assertNull($info);
    }

    public function testLoadInfoValidation_github_io()
    {
        $info = $this->loadTestDataInfo("github.io", "github.io.txt");
        self::assertEquals("github.io", $info->getDomainName());
        self::assertEquals("whois.markmonitor.com", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "ns1.p16.dynect.net",
                "ns2.p16.dynect.net",
                "ns-1622.awsdns-10.co.uk",
                "ns-692.awsdns-22.net",
                "ns-1339.awsdns-39.org",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("2013-03-08T19:12:48Z"), $info->getCreationDate());
        self::assertEquals(strtotime("2018-03-08T19:12:48Z"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "clientdeleteprohibited",
                "clienttransferprohibited",
                "clientupdateprohibited",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals("", $info->getOwner());
        self::assertEquals("MarkMonitor Inc.", $info->getRegistrar());
    }

    public function testLoadInfoValidation_google_com()
    {
        $info = $this->loadTestDataInfo("google.com", "google.com.txt");
        self::assertEquals("google.com", $info->getDomainName());
        self::assertEquals("whois.markmonitor.com", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "ns1.google.com",
                "ns2.google.com",
                "ns3.google.com",
                "ns4.google.com",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("1997-09-15T04:00:00Z"), $info->getCreationDate());
        self::assertEquals(strtotime("2020-09-14T04:00:00Z"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "clientdeleteprohibited",
                "clienttransferprohibited",
                "clientupdateprohibited",
                "serverdeleteprohibited",
                "servertransferprohibited",
                "serverupdateprohibited",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals("", $info->getOwner());
        self::assertEquals("MarkMonitor Inc.", $info->getRegistrar());
    }

    public function testLoadInfoValidation_google_com_registrar_whois()
    {
        $info = $this->loadTestDataInfo("google.com", "google.com_registrar_whois.txt");
        self::assertEquals("google.com", $info->getDomainName());
        self::assertEquals("whois.markmonitor.com", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "ns1.google.com",
                "ns2.google.com",
                "ns3.google.com",
                "ns4.google.com",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("1997-09-15T00:00:00-0700"), $info->getCreationDate());
        self::assertEquals(strtotime("2020-09-13T21:00:00-0700"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "clientdeleteprohibited",
                "clienttransferprohibited",
                "clientupdateprohibited",
                "serverdeleteprohibited",
                "servertransferprohibited",
                "serverupdateprohibited",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals("Google Inc.", $info->getOwner());
        self::assertEquals("MarkMonitor, Inc.", $info->getRegistrar());
    }

    public function testLoadInfoValidation_google_ru()
    {
        $info = $this->loadTestDataInfo("google.ru", "google.ru.txt");
        self::assertEquals("google.ru", $info->getDomainName());
        self::assertEquals("", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "ns1.google.com",
                "ns2.google.com",
                "ns3.google.com",
                "ns4.google.com",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("2004-03-03T21:00:00Z"), $info->getCreationDate());
        self::assertEquals(strtotime("2018-03-04T21:00:00Z"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "registered",
                "delegated",
                "verified",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals("Google Inc.", $info->getOwner());
        self::assertEquals("RU-CENTER-RU", $info->getRegistrar());
    }

    public function testLoadInfoValidation_info_info()
    {
        $info = $this->loadTestDataInfo("info.info", "info.info.txt");
        self::assertEquals("info.info", $info->getDomainName());
        self::assertEquals("", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "ns1.ams1.afilias-nst.info",
                "ns1.mia1.afilias-nst.info",
                "ns1.sea1.afilias-nst.info",
                "ns1.yyz1.afilias-nst.info",
                "ns1.hkg1.afilias-nst.info",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("2001-10-08T16:33:16Z"), $info->getCreationDate());
        self::assertEquals(strtotime("2018-10-08T16:33:16Z"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "servertransferprohibited",
                "autorenewperiod",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals("Afilias", $info->getOwner());
        self::assertEquals("Afilias", $info->getRegistrar());
    }

    public function testLoadInfoValidation_linux_org()
    {
        $info = $this->loadTestDataInfo("linux.org", "linux.org.txt");
        self::assertEquals("linux.org", $info->getDomainName());
        self::assertEquals("", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "mark.ns.cloudflare.com",
                "lia.ns.cloudflare.com",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("1994-05-10T04:00:00Z"), $info->getCreationDate());
        self::assertEquals(strtotime("2018-05-11T04:00:00Z"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "clienttransferprohibited",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals("Linux Online, Inc", $info->getOwner());
        self::assertEquals("Network Solutions, LLC", $info->getRegistrar());
    }

    public function testLoadInfoValidation_speedtest_net()
    {
        $info = $this->loadTestDataInfo("speedtest.net", "speedtest.net.txt");
        self::assertEquals("speedtest.net", $info->getDomainName());
        self::assertEquals("whois.enom.com", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "ns-1071.awsdns-05.org",
                "ns-1643.awsdns-13.co.uk",
                "ns-372.awsdns-46.com",
                "ns-787.awsdns-34.net",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("1999-06-25T05:27:48Z"), $info->getCreationDate());
        self::assertEquals(strtotime("2022-06-25T05:27:48Z"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "clienttransferprohibited",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals("", $info->getOwner());
        self::assertEquals("eNom, Inc.", $info->getRegistrar());
    }

    public function testLoadInfoValidation_speedtest_net_registrar_whois()
    {
        $info = $this->loadTestDataInfo("speedtest.net", "speedtest.net_registrar_whois.txt");
        self::assertEquals("speedtest.net", $info->getDomainName());
        self::assertEquals("whois.enom.com", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "ns-1071.awsdns-05.org",
                "ns-1643.awsdns-13.co.uk",
                "ns-372.awsdns-46.com",
                "ns-787.awsdns-34.net",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("1999-06-25T05:27:00.00Z"), $info->getCreationDate());
        self::assertEquals(strtotime("2022-06-25T05:27:00.00Z"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "clienttransferprohibited",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals("OOKLA, LLC.", $info->getOwner());
        self::assertEquals("ENOM, INC.", $info->getRegistrar());
    }

    public function testLoadInfoValidation_xn__80a1acny_xn__p1ai()
    {
        $info = $this->loadTestDataInfo("xn--80a1acny.xn--p1ai", "xn--80a1acny.xn--p1ai.txt");
        self::assertEquals("xn--80a1acny.xn--p1ai", $info->getDomainName());
        self::assertEquals("", $info->getWhoisServer());
        self::assertEquals(
            self::sort([
                "dc-ns1.russianpost.ru",
                "ns2.russianpost.ru",
            ]),
            self::sort($info->getNameServers())
        );
        self::assertEquals(strtotime("2010-08-23T10:32:37Z"), $info->getCreationDate());
        self::assertEquals(strtotime("2018-08-23T11:32:37Z"), $info->getExpirationDate());
        self::assertEquals(
            self::sort([
                "registered",
                "delegated",
                "verified",
            ]),
            self::sort($info->getStates())
        );
        self::assertEquals('FSUE "Russian Post"', $info->getOwner());
        self::assertEquals("RUCENTER-RF", $info->getRegistrar());
    }

    public function testLoadInfoValidation_usa_gov()
    {
        $info = $this->loadTestDataInfo("usa.gov", "usa.gov.txt");
        self::assertEquals("usa.gov", $info->getDomainName());
        self::assertEquals("", $info->getWhoisServer());
        self::assertEquals([], $info->getNameServers());
        self::assertEquals(0, $info->getCreationDate());
        self::assertEquals(0, $info->getExpirationDate());
        self::assertEquals([ "active" ], $info->getStates());
        self::assertEquals("", $info->getOwner());
        self::assertEquals("", $info->getRegistrar());
    }
}
