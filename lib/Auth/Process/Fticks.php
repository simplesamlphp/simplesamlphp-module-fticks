<?php
/**
 * Filter to log F-ticks stats data
 * See also:
 * - https://wiki.geant.org/display/gn42jra3/F-ticks+standard
 * - https://tools.ietf.org/html/draft-johansson-fticks-00
 *
 * @author Guy Halse, http://orcid.org/0000-0002-9388-8592
 * @copyright Copyright (c) 2018, South African Identity Federation
 * @package SimpleSAMLphp
 */
class sspmod_fticks_Auth_Process_Fticks extends SimpleSAML_Auth_ProcessingFilter
{
    /** @var string F-ticks version number */
    private static $_fticksVersion = '1.0';

    /** @var string F-ticks federation identifier */
    private $federation;

    /** @var string A salt to apply when digesting usernames (defaults to config file salt) */
    private $salt;

    /** @var string The username attribute to use */
    private $userId = false;

    /** @var string The realm attribute to use */
    private $realm = false;

    /** @var string The hashing algorithm to use */
    private $algorithm = 'sha256';

    /** @var array F-ticks attributes to exclude */
    private $exclude = array();

    /**
     * Generate a PN hash
     *
     * @param array $state
     * @return string $hash
     * @throws \SimpleSAML\Error\Exception
     */
    private function _generatePNhash(&$state) {
        /* get a user id */
        if ($this->userId !== false) {
            assert('array_key_exists("Attributes", $state)');
            if (array_key_exists($this->userId, $state['Attributes'])) {
                if (is_array($state['Attributes'][$this->userId])) {
                    $uid = (array_values($state['Attributes'][$this->userId]))[0];
                } else {
                    $uid = $state['Attributes'][$this->userId];
                }
            }
        } elseif (array_key_exists('UserID', $state)) {
            $uid = $state['UserID'];
        }
        /* calculate a hash */
        if (isset($uid) and is_string($uid)) {
            $userdata = $this->federation;
            if (array_key_exists('saml:sp:IdP', $state)) {
                $userdata .= strlen($state['saml:sp:IdP']).':'.$state['saml:sp:IdP'];
            } else {
                $userdata .= strlen($state['Source']['entityid']).':'.$state['Source']['entityid'];
            }
            $userdata .= strlen($state['Destination']['entityid']).':'.$state['Destination']['entityid'];
            $userdata .= strlen($uid).':'.$uid;
            $userdata .= $this->salt;

            return hash($this->algorithm, $userdata);
        }
        return false;
    }
    
    /**
     * Escape F-ticks values
     *
     * value = 1*( ALPHA / DIGIT / '_' / '-' / ':' / '.' / ',' / ';')
     * ... but add a / for entityIDs
     *
     * @param string $value
     * @return string $value
     */
    private function _escapeFticks($value)
    {
        return preg_replace('/[^A-Za-z0-9_\-:.,;\/]+/', '', $value);
    }

    /**
     * Initialize this filter, parse configuration.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     * @throws \SimpleSAML\Error\Exception
     */
    public function __construct($config, $reserved)
    {
        assert('is_array($config)');
        parent::__construct($config, $reserved);

        if (array_key_exists('federation', $config)) {
            if (is_string($config['federation'])) {
                $this->federation = $config['federation'];
            } else {
                throw new \SimpleSAML\Error\Exception('Federation identifier must be a string');
            }
        } else {
            throw new \SimpleSAML\Error\Exception('Federation identifier must be set');
        }

        if (array_key_exists('salt', $config)) {
            if (is_string($config['salt'])) {
                $this->salt = $config['salt'];
            } else {
                throw new \SimpleSAML\Error\Exception('Salt must be a string');
            }
        } else {
            $this->salt = \SimpleSAML\Utils\Config::getSecretSalt();
        }

        if (array_key_exists('userId', $config)) {
            if (is_string($config['userId'])) {
                $this->userId = $config['userId'];
            } else {
                throw new \SimpleSAML\Error\Exception('UserId must be a string');
            }
        }

        if (array_key_exists('realm', $config)) {
            if (is_string($config['realm'])) {
                $this->realm = $config['realm'];
            } else {
                throw new \SimpleSAML\Error\Exception('realm must be a string');
            }
        }

        if (array_key_exists('algorithm', $config)) {
            if (is_string($config['algorithm'])
                and in_array($config['algorithm'], hash_algos())
            ) {
                $this->algorithm = $config['algorithm'];
            } else {
                throw new \SimpleSAML\Error\Exception('algorithm must be a hash algorithm listed in hash_algos()');
            }
        }

        if (array_key_exists('exclude', $config)) {
            if (is_array($config['exclude'])) {
                $this->exclude = $config['exclude'];
            } elseif (is_string($config['exclude'])) {
                $this->exclude = array($config['exclude']);
            } else {
                throw new \SimpleSAML\Error\Exception('exclude must be an array');
            }
        }
    }

    /**
     * Process this filter
     *
     * @param mixed &$state
     */
    public function process(&$state)
    {
        assert('is_array($state)');
        assert('array_key_exists("Destination", $state)');
        assert('array_key_exists("entityid", $state["Destination"])');
        assert('array_key_exists("Source", $state)');
        assert('array_key_exists("entityid", $state["Source"])');

        $fticks = array();

        /* AFAIK the AuthProc will only execute if there is prior success */
        $fticks['RESULT'] = 'OK';

        /* SAML IdP entity Id */
        if (array_key_exists('saml:sp:IdP', $state)) {
            $fticks['AP'] = $state['saml:sp:IdP'];
        } else {
            $fticks['AP'] = $state['Source']['entityid'];
        }

        /* SAML SP entity Id */
        $fticks['RP'] = $state['Destination']['entityid'];

        /* SAML session id */
        $session = \SimpleSAML_Session::getSessionFromRequest();
        $fticks['CSI'] = $session->getTrackID();

        /* Authentication method identifier */
        if (array_key_exists('saml:sp:State', $state) and array_key_exists('saml:sp:AuthnContext', $state['saml:sp:State'])) {
            $fticks['AM'] = $state['saml:sp:State']['saml:sp:AuthnContext'];
        } elseif (array_key_exists('SimpleSAML_Auth_State.stage', $state) and preg_match('/UserPass/', $state['SimpleSAML_Auth_State.stage'])) {
            /* hack to try identify LDAP et al as Password */
            $fticks['AM'] = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password';
        }

        /* ePTID */
        $pn = $this->_generatePNhash($state);
        if ($pn !== false) {
            $fticks['PN'] = $pn;
        }

        /* timestamp */
        if (array_key_exists('saml:sp:State', $state) and array_key_exists('saml:AuthnInstant', $state['saml:sp:State'])) {
            $fticks['TS'] = $state['saml:sp:State']['saml:AuthnInstant'];
        } else {
            $fticks['TS'] = time();
        }

        /* realm */
        if ($this->realm !== false) {
            assert('array_key_exists("Attributes", $state)');
            if (array_key_exists($this->realm, $state['Attributes'])) {
                if (is_array($state['Attributes'][$this->realm])) {
                    $fticks['REALM'] = (array_values($state['Attributes'][$this->realm]))[0];
                } else {
                    $fticks['REALM'] = $state['Attributes'][$this->realm];
                }
            }
        }

        /* allow some attributes to be excluded */
        if ($this->exclude !== false) {
            $fticks = array_filter(
                $fticks,
                function($k) {
                    return !in_array($k, $this->exclude);
                },
                ARRAY_FILTER_USE_KEY
            );
        }

        \SimpleSAML\Logger::stats(
            'F-TICKS/'.$this->federation.'/'.self::$_fticksVersion.'#' .
            implode('#', array_map(
                function($k, $v) {
                    return $k.'='.$this->_escapeFticks($v);
                },
                array_keys($fticks),
                $fticks
            )) .
            '#'
        );
    }
}
