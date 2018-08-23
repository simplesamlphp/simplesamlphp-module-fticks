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
            'logging.format' => '%msg',
        ), '[ARRAY]', 'simplesaml');
        /*
        $rm = new ReflectionMethod('SimpleSAML\Logger', 'createLoggingHandler');
        $rm->setAccessible(true);
        $rm->invoke('SimpleSAML\Logger\StandardErrorLoggingHandler');
        */
    }

    public function testMinimal()
    {
        $config = array('federation' => 'ACME',);
        $request = self::$_minrequest;
        $result = self::processFilter($config, $request);
    }

    public function testAsServiceProvider()
    {
        $config = array('federation' => 'ACME',);
        $request = array_merge(self::$_minrequest, self::$_sprequest);
        $result = self::processFilter($config, $request);
    }

    public function testSPwithUserId()
    {
        $config = array('federation' => 'ACME', 'userId' => 'eduPersonPrincipalName');
        $request = array_merge(self::$_minrequest, self::$_sprequest, array(
            'Attributes' => array(
                'eduPersonPrincipalName' => 'user2@example.net',
            ),
        ));
        $result = self::processFilter($config, $request);
    }

    public function testAsIdentityProvider()
    {
        $config = array('federation' => 'ACME',);
        $request = array_merge(self::$_minrequest, self::$_idprequest);
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
        );
        $request = array_merge(self::$_minrequest, self::$_idprequest, array(
            'Attributes' => array(
                'eduPersonPrincipalName' => 'user3@example.com',
                'schacHomeOrganization' => 'example.com',
            ),
        ));
        $result = self::processFilter($config, $request);
    }

    public function testFilteringArray()
    {
        $config = array('federation' => 'ACME', 'exclude' => array('PN', 'AM'));
        $request = array_merge(self::$_minrequest, self::$_idprequest);
        $result = self::processFilter($config, $request);
    }

    public function testFilteringString()
    {
        $config = array('federation' => 'ACME', 'exclude' => 'AM');
        $request = array_merge(self::$_minrequest, self::$_idprequest);
        $result = self::processFilter($config, $request);
    }
}
