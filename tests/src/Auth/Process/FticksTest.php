<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\fticks\Auth\Process;

use PHPUnit\Framework\Attributes\BackupStaticProperties;
use PHPUnit\Framework\TestCase;
use SAML2\Constants;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\fticks\Auth\Process\Fticks;

use function array_merge;
use function preg_quote;

final class FticksTest extends TestCase
{
    /** @var array minimal request */
    private static $minRequest = [
        'Source' => [
            'entityid' => 'https://localhost/sp',
        ],
        'Destination' => [
            'entityid' => 'https://localhost/idp',
        ],
        'Attributes' => [],
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
        $_SERVER['REQUEST_URI'] = '/simplesaml/'; /* suppress warning from SimpleSAML/Utils/HTTP */
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
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern . '[^#]+#TS=\d+#$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testAsServiceProvider(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout'];
        $request = array_merge(self::$minRequest, self::$spRequest);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified#TS=1000#', '/');
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testSPwithUserId(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'identifyingAttribute' => 'eduPersonPrincipalName'];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => [ 'user2@example.net' ],
            ],
        ]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_UNSPECIFIED
            . '#PN=d63bb55765af1321b06950abb5f9787cffd05ef271a09b67964f402f3f209cc6#TS=1000#',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testSPwithUserIdDifferentProviders(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'identifyingAttribute' => 'eduPersonPrincipalName'];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => [ 'user2@example.net' ],
            ],
        ]);
        $request['Destination']['entityid'] = 'https://localhost/idp2';
        $request['saml:sp:IdP'] = 'https://localhost/saml:sp:IdP2';
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP2#RP=https://localhost/idp2#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_UNSPECIFIED
            . '#PN=d63bb55765af1321b06950abb5f9787cffd05ef271a09b67964f402f3f209cc6#TS=1000#',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testSPwithUserIdLegacyBehaviour(): void
    {
        $config = [
            'federation' => 'ACME',
            'logdest' => 'stdout',
            'identifyingAttribute' => 'eduPersonPrincipalName',
            'pnHashIsTargeted' => 'both',
        ];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => [ 'user2@example.net' ],
            ],
        ]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_UNSPECIFIED
            . '#PN=e5d066a96d5809a21264e153013c3c793e6574cb77afdfa248ad2cefab9b0451#TS=1000#',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testSPwithUserIdSourceTargeted(): void
    {
        $config = [
            'federation' => 'ACME',
            'logdest' => 'stdout',
            'identifyingAttribute' => 'eduPersonPrincipalName',
            'pnHashIsTargeted' => 'source',
        ];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => [ 'user2@example.net' ],
            ],
        ]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_UNSPECIFIED
            . '#PN=d9b260a0830f4a93b407aaf0a578446880fc8acdc58cd81aecdcde12ec0f8cae#TS=1000#',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testSPwithUserIdSourceTargetedDifferentDest(): void
    {
        $config = [
            'federation' => 'ACME',
            'logdest' => 'stdout',
            'identifyingAttribute' => 'eduPersonPrincipalName',
            'pnHashIsTargeted' => 'source',
        ];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => [ 'user2@example.net' ],
            ],
        ]);
        $request['Destination']['entityid'] = 'https://localhost/idp2';
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp2#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_UNSPECIFIED
            . '#PN=d9b260a0830f4a93b407aaf0a578446880fc8acdc58cd81aecdcde12ec0f8cae#TS=1000#',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testSPwithUserIdDestinationTargeted(): void
    {
        $config = [
            'federation' => 'ACME',
            'logdest' => 'stdout',
            'identifyingAttribute' => 'eduPersonPrincipalName',
            'pnHashIsTargeted' => 'destination',
        ];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => [ 'user2@example.net' ],
            ],
        ]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_UNSPECIFIED
            . '#PN=2497368e277bd4d6f848c268292e85cbe3fe4dfd0920b4ac2f5a419f523d4374#TS=1000#',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
        $request['saml:sp:IdP'] = 'https://localhost/saml:sp:IdP2';
    }


    /**
     */
    public function testSPwithUserIdDestinationTargetedDifferentSource(): void
    {
        $config = [
            'federation' => 'ACME',
            'logdest' => 'stdout',
            'identifyingAttribute' => 'eduPersonPrincipalName',
            'pnHashIsTargeted' => 'destination',
        ];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => [ 'user2@example.net' ],
            ],
        ]);
        $request['saml:sp:IdP'] = 'https://localhost/saml:sp:IdP2';
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP2#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_UNSPECIFIED
            . '#PN=2497368e277bd4d6f848c268292e85cbe3fe4dfd0920b4ac2f5a419f523d4374#TS=1000#',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testAsIdentityProvider(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'identifyingAttribute' => 'uid'];
        $request = array_merge(self::$minRequest, self::$idpRequest, [
            'Attributes' => [
                'uid' => 'user1@example.org', /* deliberately not an array to test different code path */
            ],
        ]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=' . Constants::AC_PASSWORD
            . '#PN=16ed2263078ca90f38708681fcf6628d80e0f91f4b5d743054fe8e185c9e0979#TS=',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '\d+#$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
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
                'eduPersonPrincipalName' => [ 'user3@example.com' ],
                'schacHomeOrganization' => [ 'example.com' ],
            ],
        ]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:Password#TS=',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '\d+#REALM=example.com#$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testFilteringArray(): void
    {
        $config = [
            'federation' => 'ACME',
            'logdest' => 'stdout',
            'exclude' => ['PN', 'AM'],
            'identifyingAttribute' => 'uid',
        ];
        $request = array_merge(self::$minRequest, self::$idpRequest, ['Attributes' => ['uid' => 'user1@example.org']]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+#TS=\d+#$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testFilteringString(): void
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'exclude' => 'AM', 'identifyingAttribute' => 'uid'];
        $request = array_merge(self::$minRequest, self::$idpRequest, ['Attributes' => ['uid' => 'user1@example.org']]);
        $pattern1 = preg_quote(
            'F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL',
            '/',
        );
        $pattern2 = preg_quote(
            '#PN=16ed2263078ca90f38708681fcf6628d80e0f91f4b5d743054fe8e185c9e0979#TS=',
            '/',
        );
        $this->expectOutputRegex('/^' . $pattern1 . '[^#]+' . $pattern2 . '\d+#$/');
        $result = self::processFilter($config, $request);
        $this->assertEquals($request, $result);
    }


    /**
     */
    public function testInvalidConfig(): void
    {
        $this->expectException(Error\Exception::class);
        self::processFilter([], self::$minRequest);
        self::processFilter(['federation' => 'ACME', 'logdest' => 'invalid'], self::$minRequest);
    }

    /**
      */
    #[BackupStaticProperties(true)]
    public function testRiskyLogSettings(): void
    {
        Logger::setCaptureLog();
        self::processFilter(
            ['federation' => 'ACME', 'logdest' => 'local', 'logconfig' => ['processname' => 'phpunit']],
            self::$minRequest,
        );
        $log = Logger::getCapturedLog();
        $this->assertCount(1, $log);
        $this->assertStringContainsString('syslog processname differs from global config', $log[0]);
    }
}
