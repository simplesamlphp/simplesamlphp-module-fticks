<?php

namespace SimpleSAML\Module\fticks\Auth\Process;

use SAML2\Constants;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Session;
use SimpleSAML\Utils;

/**
 * Filter to log F-ticks stats data
 * See also:
 * - https://wiki.geant.org/display/gn42jra3/F-ticks+standard
 * - https://tools.ietf.org/html/draft-johansson-fticks-00
 *
 * @author    Guy Halse, http://orcid.org/0000-0002-9388-8592
 * @copyright Copyright (c) 2019, South African Identity Federation
 * @package   SimpleSAMLphp
 */
class Fticks extends \SimpleSAML\Auth\ProcessingFilter
{
    /** @var string F-ticks version number */
    private static $fticksVersion = '1.0';

    /** @var string F-ticks federation identifier */
    private $federation;

    /** @var string A salt to apply when digesting usernames (defaults to config file salt) */
    private $salt;

    /** @var string The logging backend */
    private $logdest = 'simplesamlphp';

    /** @var array Backend specific logging config */
    private $logconfig = [];

    /** @var string|false The username attribute to use */
    private $userId = false;

    /** @var string|false The realm attribute to use */
    private $realm = false;

    /** @var string The hashing algorithm to use */
    private $algorithm = 'sha256';

    /** @var array|false F-ticks attributes to exclude */
    private $exclude = false;


    /**
     * Log a message to the desired destination
     *
     * @param  string $msg message to log
     * @return void
     */
    private function log($msg)
    {
        switch ($this->logdest) {
            /* local syslog call, avoiding SimpleSAMLphp's wrapping */
            case 'local':
            case 'syslog':
                assert(array_key_exists("processname", $this->logconfig));
                assert(array_key_exists("facility", $this->logconfig));
                openlog($this->logconfig['processname'], LOG_PID, $this->logconfig['facility']);
                syslog(array_key_exists('priority', $this->logconfig) ? $this->logconfig['priority'] : LOG_INFO, $msg);
                break;

            /* remote syslog call via UDP */
            case 'remote':
                assert(array_key_exists("processname", $this->logconfig));
                assert(array_key_exists("facility", $this->logconfig));
                /* assemble a syslog message per RFC 5424 */
                $rfc5424_message = sprintf(
                    '<%d>',
                    ((($this->logconfig['facility'] & 0x03f8) >> 3) * 8) +
                    (array_key_exists('priority', $this->logconfig) ? $this->logconfig['priority'] : LOG_INFO)
                ); // pri
                $rfc5424_message .= '1 '; // ver
                $rfc5424_message .= gmdate('Y-m-d\TH:i:s.v\Z '); // timestamp
                $rfc5424_message .= gethostname() . ' '; // hostname
                $rfc5424_message .= $this->logconfig['processname'] . ' '; // app-name
                $rfc5424_message .= posix_getpid() . ' '; // procid
                $rfc5424_message .= '- '; // msgid
                $rfc5424_message .= '- '; // structured-data
                $rfc5424_message .= $msg;
                /* send it to the remote host */
                $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
                socket_sendto(
                    $sock,
                    $rfc5424_message,
                    strlen($rfc5424_message),
                    0,
                    gethostbyname(array_key_exists('host', $this->logconfig) ? $this->logconfig['host'] : 'localhost'),
                    array_key_exists('port', $this->logconfig) ? $this->logconfig['port'] : 514
                );
                break;

            case 'errorlog':
                error_log($msg);
                break;

            /* mostly for unit testing */
            case 'stdout':
                echo $msg . "\n";
                break;

            /* SimpleSAMLphp's builtin logging */
            case 'simplesamlphp':
            default:
                Logger::stats($msg);
                break;
        }
    }


    /**
     * Generate a PN hash
     *
     * @param  array $state
     * @return string|false $hash
     * @throws \SimpleSAML\Error\Exception
     */
    private function generatePNhash(&$state)
    {
        /* get a user id */
        if ($this->userId !== false) {
            assert(array_key_exists("Attributes", $state));
            if (array_key_exists($this->userId, $state['Attributes'])) {
                if (is_array($state['Attributes'][$this->userId])) {
                    $uid = $state['Attributes'][$this->userId][0];
                } else {
                    $uid = $state['Attributes'][$this->userId];
                }
            }
        } elseif (array_key_exists('UserID', $state)) {
            $uid = $state['UserID'];
        }

        /* calculate a hash */
        if (isset($uid) && is_string($uid)) {
            $userdata = $this->federation;
            if (array_key_exists('saml:sp:IdP', $state)) {
                $userdata .= strlen($state['saml:sp:IdP']) . ':' . $state['saml:sp:IdP'];
            } else {
                $userdata .= strlen($state['Source']['entityid']) . ':' . $state['Source']['entityid'];
            }
            $userdata .= strlen($state['Destination']['entityid']) . ':' . $state['Destination']['entityid'];
            $userdata .= strlen($uid) . ':' . $uid;
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
     * @param  string $value
     * @return string $value
     */
    private function escapeFticks($value)
    {
        return preg_replace('/[^A-Za-z0-9_\-:.,;\/]+/', '', $value);
    }


    /**
     * Initialize this filter, parse configuration.
     *
     * @param  array $config Configuration information about this filter.
     * @param  mixed $reserved For future use.
     * @throws \SimpleSAML\Error\Exception
     */
    public function __construct($config, $reserved)
    {
        assert(is_array($config));
        parent::__construct($config, $reserved);

        if (array_key_exists('federation', $config)) {
            if (is_string($config['federation'])) {
                $this->federation = $config['federation'];
            } else {
                throw new \Exception('Federation identifier must be a string');
            }
        } else {
            throw new \Exception('Federation identifier must be set');
        }

        if (array_key_exists('salt', $config)) {
            if (is_string($config['salt'])) {
                $this->salt = $config['salt'];
            } else {
                throw new \Exception('Salt must be a string');
            }
        } else {
            $this->salt = Utils\Config::getSecretSalt();
        }

        if (array_key_exists('userId', $config)) {
            if (is_string($config['userId'])) {
                $this->userId = $config['userId'];
            } else {
                throw new \Exception('UserId must be a string');
            }
        }

        if (array_key_exists('realm', $config)) {
            if (is_string($config['realm'])) {
                $this->realm = $config['realm'];
            } else {
                throw new \Exception('realm must be a string');
            }
        }

        if (array_key_exists('algorithm', $config)) {
            if (
                is_string($config['algorithm'])
                && in_array($config['algorithm'], hash_algos())
            ) {
                $this->algorithm = $config['algorithm'];
            } else {
                throw new \Exception('algorithm must be a hash algorithm listed in hash_algos()');
            }
        }

        if (array_key_exists('exclude', $config)) {
            if (is_array($config['exclude'])) {
                $this->exclude = $config['exclude'];
            } elseif (is_string($config['exclude'])) {
                $this->exclude = [$config['exclude']];
            } else {
                throw new \Exception('F-ticks exclude must be an array');
            }
        }

        if (array_key_exists('logdest', $config)) {
            if (
                is_string($config['logdest']) &&
                in_array($config['logdest'], ['local', 'syslog', 'remote', 'stdout', 'errorlog', 'simplesamlphp'])
            ) {
                $this->logdest = $config['logdest'];
            } else {
                throw new \Exception(
                    'F-ticks log destination must be one of [local, remote, stdout, errorlog, simplesamlphp]'
                );
            }
        }

        /* match SSP config or we risk mucking up the openlog call */
        $globalConfig = Configuration::getInstance();
        $defaultFacility = $globalConfig->getInteger(
            'logging.facility',
            defined('LOG_LOCAL5') ? constant('LOG_LOCAL5') : LOG_USER
        );
        $defaultProcessName = $globalConfig->getString('logging.processname', 'SimpleSAMLphp');
        if (array_key_exists('logconfig', $config)) {
            if (is_array($config['logconfig'])) {
                $this->logconfig = $config['logconfig'];
            } else {
                throw new \Exception('F-ticks logconfig must be an array');
            }
        }
        if (!array_key_exists('facility', $this->logconfig)) {
            $this->logconfig['facility'] = $defaultFacility;
        }
        if (!array_key_exists('processname', $this->logconfig)) {
            $this->logconfig['processname'] = $defaultProcessName;
        }
        /* warn if we risk mucking up the openlog call (doesn't matter for remote syslog) */
        if (in_array($this->logdest, ['local', 'syslog'])) {
            if (
                array_key_exists('facility', $this->logconfig)
                && ($this->logconfig['facility'] !== $defaultFacility)
            ) {
                Logger::warning(
                    'F-ticks syslog facility differs from global config which may cause'
                    . ' SimpleSAMLphp\'s logging to behave inconsistently'
                );
            }
            if (
                array_key_exists('processname', $this->logconfig)
                && ($this->logconfig['processname'] !== $defaultProcessName)
            ) {
                Logger::warning(
                    'F-ticks syslog processname differs from global config which may cause'
                    . ' SimpleSAMLphp\'s logging to behave inconsistently'
                );
            }
        }
    }

    /**
     * Process this filter
     *
     * @param  mixed &$state
     * @return void
     */
    public function process(&$state)
    {
        assert(is_array($state));
        assert(array_key_exists("Destination", $state));
        assert(array_key_exists("entityid", $state["Destination"]));
        assert(array_key_exists("Source", $state));
        assert(array_key_exists("entityid", $state["Source"]));

        $fticks = [];

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
        $session = Session::getSessionFromRequest();
        $fticks['CSI'] = $session->getTrackID();

        /* Authentication method identifier */
        if (
            array_key_exists('saml:sp:State', $state)
            && array_key_exists('saml:sp:AuthnContext', $state['saml:sp:State'])
        ) {
            $fticks['AM'] = $state['saml:sp:State']['saml:sp:AuthnContext'];
        } elseif (
            array_key_exists('SimpleSAML_Auth_State.stage', $state)
            && preg_match('/UserPass/', $state['SimpleSAML_Auth_State.stage'])
        ) {
            /* hack to try identify LDAP et al as Password */
            $fticks['AM'] = Constants::AC_PASSWORD;
        }

        /* ePTID */
        $pn = $this->generatePNhash($state);
        if ($pn !== false) {
            $fticks['PN'] = $pn;
        }

        /* timestamp */
        if (
            array_key_exists('saml:sp:State', $state)
            && array_key_exists('saml:AuthnInstant', $state['saml:sp:State'])
        ) {
            $fticks['TS'] = $state['saml:sp:State']['saml:AuthnInstant'];
        } else {
            $fticks['TS'] = time();
        }

        /* realm */
        if ($this->realm !== false) {
            assert(array_key_exists("Attributes", $state));
            if (array_key_exists($this->realm, $state['Attributes'])) {
                if (is_array($state['Attributes'][$this->realm])) {
                    $fticks['REALM'] = $state['Attributes'][$this->realm][0];
                } else {
                    $fticks['REALM'] = $state['Attributes'][$this->realm];
                }
            }
        }

        /* allow some attributes to be excluded */
        if ($this->exclude !== false) {
            $fticks = array_filter(
                $fticks,
                /**
                 * @param  string $k
                 * @return bool
                 */
                function ($k) {
                    return !in_array($k, $this->exclude);
                },
                ARRAY_FILTER_USE_KEY
            );
        }

        /* assemble an F-ticks log string */
        $this->log(
            'F-TICKS/' . $this->federation . '/' . self::$fticksVersion . '#' .
            implode('#', array_map(
                /**
                 * @param  string $k
                 * @param  string $v
                 * @return string
                 */
                function ($k, $v) {
                    return $k . '=' . $this->escapeFticks($v);
                },
                array_keys($fticks),
                $fticks
            )) . '#'
        );
    }
}
