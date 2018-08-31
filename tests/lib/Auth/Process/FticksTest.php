<?php
// Alias the PHPUnit 6.0 ancestor if available, else fall back to legacy ancestor
if (class_exists('\PHPUnit\Framework\TestCase', true) and !class_exists('\PHPUnit_Framework_TestCase', true)) {
    class_alias('\PHPUnit\Framework\TestCase', '\PHPUnit_Framework_TestCase', true);
}

/**
 * Test for the core:CardinalitySingle filter.
 */
class sspmod_fticks_Auth_Process_FticksTest extends \PHPUnit_Framework_TestCase
{
    private static $_minrequest = array(
        'Source' => array(
            'entityid' => 'https://localhost/sp',
        ),
        'Destination' => array(
            'entityid' => 'https://localhost/idp',
        ),
    );

    private static $_sprequest = array(
        'saml:sp:IdP' => 'https://localhost/saml:sp:IdP',
        'saml:sp:SessionIndex' => 'saml:sp:SessionIndex',
        'saml:sp:State' => array(
            'saml:sp:AuthnContext' => 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
            'saml:AuthnInstant' => 1000,
        ),
    );

    private static $_idprequest = array(
        'SimpleSAML_Auth_State.id' => 'SimpleSAML_Auth_State.id',
        'SimpleSAML_Auth_State.stage' => 'sspmod_core_Auth_UserPassBase.state',
        'UserID' => 'user1@example.org',
    );

    /**
     * Helper function to run the filter with a given configuration.
     *
     * @param  array $config The filter configuration.
     * @param  array $request The request state.
     * @return array  The state array after processing.
     */
    private static function processFilter(array $config, array $request)
    {
        $filter = new \sspmod_fticks_Auth_Process_Fticks($config, null);
        $filter->process($request);
        return $request;
    }

    protected function setUp()
    {
        \SimpleSAML_Configuration::loadFromArray(array(
            'secretsalt' => 'secretsalt',
        ), '[ARRAY]', 'simplesaml');
        /*
        $rm = new ReflectionMethod('SimpleSAML\Logger', 'createLoggingHandler');
        $rm->setAccessible(true);
        $rm->invoke('SimpleSAML\Logger\StandardErrorLoggingHandler');
        */
    }

    public function testMinimal()
    {
        $config = array('federation' => 'ACME', 'logdest' => 'stdout');
        $request = self::$_minrequest;
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL','/').'[^#]+#TS=\d+#$/');
        $result = self::processFilter($config, $request);
    }

    public function testAsServiceProvider()
    {
        $config = array('federation' => 'ACME', 'logdest' => 'stdout',);
        $request = array_merge(self::$_minrequest, self::$_sprequest);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL','/').'[^#]+'.preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified#TS=1000#','/').'$/');
        $result = self::processFilter($config, $request);
    }

    public function testSPwithUserId()
    {
        $config = array('federation' => 'ACME', 'logdest' => 'stdout', 'userId' => 'eduPersonPrincipalName');
        $request = array_merge(self::$_minrequest, self::$_sprequest, array(
            'Attributes' => array(
                'eduPersonPrincipalName' => 'user2@example.net',
            ),
        ));
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/saml:sp:IdP#RP=https://localhost/idp#CSI=CL','/').'[^#]+'.preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified#PN=e5d066a96d5809a21264e153013c3c793e6574cb77afdfa248ad2cefab9b0451#TS=1000#','/').'$/');
        $result = self::processFilter($config, $request);
    }

    public function testAsIdentityProvider()
    {
        $config = array('federation' => 'ACME', 'logdest' => 'stdout',);
        $request = array_merge(self::$_minrequest, self::$_idprequest);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL','/').'[^#]+'.preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:Password#PN=d844a9a0666bb3990e88f72b8f5c20accbcfa46f7b8a7ab38593bfbbab6e9cbc#TS=','/').'\d+#$/');
        $result = self::processFilter($config, $request);
    }

    public function testExample()
    {
        $config = array(
            'federation' => 'ACME',
            'salt' => 'someVerySecretStringDifferentFromTheDefault',
            'userId' => 'eduPersonPrincipalName',
            'realm' => 'schacHomeOrganization',
            'algorithm' => 'sha512',
            'exclude' => array('PN'),
            'logdest' => 'stdout',
        );
        $request = array_merge(self::$_minrequest, self::$_idprequest, array(
            'Attributes' => array(
                'eduPersonPrincipalName' => 'user3@example.com',
                'schacHomeOrganization' => 'example.com',
            ),
        ));
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL','/').'[^#]+'.preg_quote('#AM=urn:oasis:names:tc:SAML:2.0:ac:classes:Password#TS=','/').'\d+#REALM=example.com#$/');
        $result = self::processFilter($config, $request);
    }

    public function testFilteringArray()
    {
        $config = array('federation' => 'ACME', 'logdest' => 'stdout', 'exclude' => array('PN', 'AM'));
        $request = array_merge(self::$_minrequest, self::$_idprequest);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL','/').'[^#]+#TS=\d+#$/');
        $result = self::processFilter($config, $request);
    }

    public function testFilteringString()
    {
        $config = array('federation' => 'ACME', 'logdest' => 'stdout', 'exclude' => 'AM');
        $request = array_merge(self::$_minrequest, self::$_idprequest);
        $this->expectOutputRegex('/^'.preg_quote('F-TICKS/ACME/1.0#RESULT=OK#AP=https://localhost/sp#RP=https://localhost/idp#CSI=CL','/').'[^#]+'.preg_quote('#PN=d844a9a0666bb3990e88f72b8f5c20accbcfa46f7b8a7ab38593bfbbab6e9cbc#TS=','/').'\d+#$/');
        $result = self::processFilter($config, $request);
    }
}
