<?php

namespace SimpleSAML\Test\Module\fticks\Auth\Process;

class FticksTest extends \PHPUnit_Framework_TestCase
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
    private static $spRequest =[
        'saml:sp:IdP' => 'https://localhost/saml:sp:IdP',
        'saml:sp:SessionIndex' => 'saml:sp:SessionIndex',
        'saml:sp:State' => [
            'saml:sp:AuthnContext' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
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
    private static function processFilter(array $config, array $request)
    {
        $filter = new \SimpleSAML\Module\fticks\Auth\Process\Fticks($config, null);
        $filter->process($request);
        return $request;
    }

    /**
     * @return void
     */
    protected function setUp()
    {
        \SimpleSAML\Configuration::loadFromArray([
            'secretsalt' => 'secretsalt',
        ], '[ARRAY]', 'simplesaml');
        /*
        $rm = new ReflectionMethod('\SimpleSAML\Logger', 'createLoggingHandler');
        $rm->setAccessible(true);
        $rm->invoke('\SimpleSAML\Logger\StandardErrorLoggingHandler');
        */
    }

    /**
     * @return void
     */
    public function testMinimal()
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout'];
        $request = self::$minRequest;
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL', '/').'[^#]+#TS=\d+#$/');
        $result = self::processFilter($config, $request);
    }

    /**
     * @return void
     */
    public function testAsServiceProvider()
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout',];
        $request = array_merge(self::$minRequest, self::$spRequest);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL', '/').'[^#]+'.preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified#TS=1000#', '/').'$/');
        $result = self::processFilter($config, $request);
    }

    /**
     * @return void
     */
    public function testSPwithUserId()
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'userId' => 'eduPersonPrincipalName'];
        $request = array_merge(self::$minRequest, self::$spRequest, [
            'Attributes' => [
                'eduPersonPrincipalName' => 'user2@example.net',
            ],
        ]);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL', '/').'[^#]+'.preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified#PN=e5d066a96d5809a21264e153013c3c793e6574cb77afdfa248ad2cefab9b0451#TS=1000#', '/').'$/');
        $result = self::processFilter($config, $request);
    }

    /**
     * @return void
     */
    public function testAsIdentityProvider()
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout',];
        $request = array_merge(self::$minRequest, self::$idpRequest);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL', '/').'[^#]+'.preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:Password#PN=d844a9a0666bb3990e88f72b8f5c20accbcfa46f7b8a7ab38593bfbbab6e9cbc#TS=', '/').'\d+#$/');
        $result = self::processFilter($config, $request);
    }

    /**
     * @return void
     */
    public function testExample()
    {
        $config = [
            'federation' => 'ACME',
            'salt' => 'someVerySecretStringDifferentFromTheDefault',
            'userId' => 'eduPersonPrincipalName',
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
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL', '/').'[^#]+'.preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:Password#TS=', '/').'\d+#REALM=example.com#$/');
        $result = self::processFilter($config, $request);
    }

    /**
     * @return void
     */
    public function testFilteringArray()
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'exclude' => ['PN', 'AM']];
        $request = array_merge(self::$minRequest, self::$idpRequest);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL', '/').'[^#]+#TS=\d+#$/');
        $result = self::processFilter($config, $request);
    }

    /**
     * @return void
     */
    public function testFilteringString()
    {
        $config = ['federation' => 'ACME', 'logdest' => 'stdout', 'exclude' => 'AM'];
        $request = array_merge(self::$minRequest, self::$idpRequest);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL', '/').'[^#]+'.preg_quote('#PN=d844a9a0666bb3990e88f72b8f5c20accbcfa46f7b8a7ab38593bfbbab6e9cbc#TS=', '/').'\d+#$/');
        $result = self::processFilter($config, $request);
    }
}
