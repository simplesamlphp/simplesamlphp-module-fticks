<?php

namespace SimpleSAML\Test\Module\fticks\Auth\Process;

use PHPUnit\Framework\TestCase;
use SAML2\Constants;
use SimpleSAML\Module\fticks\Auth\Process\Fticks;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Logger\StandardErrorLoggingHandler;

use function array_merge;
use function preg_quote;

class FticksTest extends TestCase
{
    /** @var array minimal request */
    private static $minRequest = [
        'Source' => [
            'entityid' => 'https://localhost/sp',
        ],
        'Destination' => [
            'entityid' => 'https://localhost/idp',
        ],
    ];

    /** @var array SP request */
    private static $spRequest = [
        'saml:sp:IdP' => 'https://localhost/saml:sp:IdP',
        'saml:sp:SessionIndex' => 'saml:sp:SessionIndex',
        'saml:sp:State' => [
            'saml:sp:AuthnContext' => Constants::AC_UNSPECIFIED,
            'saml:AuthnInstant' => 1000,
        ],
    ];

    /** @var array IdP request */
    private static $idpRequest = [
        'SimpleSAML_Auth_State.id' => 'SimpleSAML_Auth_State.id',
        'SimpleSAML_Auth_State.stage' => 'sspmod_core_Auth_UserPassBase.state',
        'UserID' => 'user1@example.org',
    ];


    /**
     * Helper function to run the filter with a given configuration.
     *
     * @param  array $config The filter configuration.
     * @param  array $request The request state.
     * @return array  The state array after processing.
     */
    private static function processFilter(array $config, array $request): array
    {
        $filter = new Fticks($config, null);
        $filter->process($request);
        return $request;
    }


    /**
     */
    protected function setUp(): void
    {
        Configuration::loadFromArray([
            'secretsalt' => 'secretsalt',
        ], '[ARRAY]', 'simplesaml');
    }


    /**
     */
    public function testMinimal(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout'];
        $request = self::$minRequest;
        $pattern = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/'
        );
        $this->expectOutputRegex('/^' . $pattern . '[^#]+#TS=\d+#$/');
        $result = self::processFilter($config, $request);
    }


    /**
     */
    public function testAsServiceProvider(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout',];
        $request = array_merge(self::$minRequest, self::$spRequest);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL',
            '/'
        );
        $pattern2 = preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified#TS=1000#', '/');
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
    }


    /**
     */
    public function testSPwithUserId(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'userId' => 'eduPersonPrincipalName'];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => 'user2@example.net',
            ],
        ]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL',
            '/'
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_UNSPECIFIED
            . '#PN=e5d066a96d5809a21264e153013c3c793e6574cb77afdfa248ad2cefab9b0451#TS=1000#',
            '/'
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
    }


    /**
     */
    public function testAsIdentityProvider(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'identifyingAttribute' => 'uid'];
        $request = array_merge(self::$minRequest, self::$idpRequest, ['Attributes' => ['uid' => 'user1@example.org']]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/'
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_PASSWORD
            . '#PN=d844a9a0666bb3990e88f72b8f5c20accbcfa46f7b8a7ab38593bfbbab6e9cbc#TS=',
            '/'
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '\d+#$/');
        $result = self::processFilter($config, $request);
    }


    /**
     */
    public function testExample(): void
    {
        $config = [
            'federation' => 'ACME',
            'salt' => 'someVerySecretStringDifferentFromTheDefault',
            'identifyingAttribute' => 'eduPersonPrincipalName',
            'realm' => 'schacHomeOrganization',
            'algorithm' => 'sha512',
            'exclude' => ['PN'],
            'logdest' => 'stdout',
        ];
        $request = array_merge(self::$minRequest, self::$idpRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => 'user3@example.com',
                'schacHomeOrganization' => 'example.com',
            ],
        ]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/'
        );
        $pattern2 = preg_quote(
            '#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:Password#TS=',
            '/'
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '\d+#REALM=example.com#$/');
        $result = self::processFilter($config, $request);
    }


    /**
     */
    public function testFilteringArray(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'exclude' => ['PN', 'AM'], 'identifyingAttribute' => 'uid'];
        $request = array_merge(self::$minRequest, self::$idpRequest, ['Attributes' => ['uid' => 'user1@example.org']]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/'
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+#TS=\d+#$/');
        $result = self::processFilter($config, $request);
    }


    /**
     */
    public function testFilteringString(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'exclude' => 'AM', 'identifyingAttribute' => 'uid'];
        $request = array_merge(self::$minRequest, self::$idpRequest, ['Attributes' => ['uid' => 'user1@example.org']]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/'
        );
        $pattern2 = preg_quote(
            '#PN=654600d0303209530fdd0bfd6ee63466c5618e35b2a4c094cfac236fe3621e8b#TS=',
            '/'
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '\d+#$/');
        $result = self::processFilter($config, $request);
    }
}
