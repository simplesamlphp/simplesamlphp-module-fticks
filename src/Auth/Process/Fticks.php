<?php

declare(strict_types=1);

namespace SimpleSAML\Module\fticks\Auth\Process;

use SAML2\Constants;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Session;
use SimpleSAML\Utils;

use function array_filter;
use function array_keys;
use function array_key_exists;
use function array_map;
use function constant;
use function defined;
use function gethostbyname;
use function gethostname;
use function gmdate;
use function hash;
use function hash_algos;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function openlog;
use function posix_getpid;
use function preg_match;
use function preg_replace;
use function socket_create;
use function socket_sendto;
use function sprintf;
use function strlen;
use function syslog;

/**
 * Filter to log F-ticks stats data
 * See also:
 * - https://wiki.geant.org/display/gn42jra3/F-ticks+standard
 * - https://tools.ietf.org/html/draft-johansson-fticks-00
 *
 * @copyright Copyright (c) 2019, South African Identity Federation
 * @package   SimpleSAMLphp
 */
class Fticks extends Auth\ProcessingFilter
{
    /** @var string F-ticks version number */
    private static string $fticksVersion = '1.0';

    /** @var string F-ticks federation identifier */
    private string $federation;

    /** @var string A salt to apply when digesting usernames (defaults to config file salt) */
    private string $salt;

    /** @var string The logging backend */
    private string $logdest = 'simplesamlphp';

    /** @var array Backend specific logging config */
    private array $logconfig = [];

    /** @var string The username attribute to use */
    private string $identifyingAttribute = 'eduPersonPrincipalName';

    /** @var string|false The realm attribute to use */
    private $realm = false;

    /** @var string The hashing algorithm to use */
    private string $algorithm = 'sha256';

    /** @var array|false F-ticks attributes to exclude */
    private $exclude = false;


    /**
     * Log a message to the desired destination
     *
     * @param  string $msg message to log
     */
    private function log(string $msg): void
    {
        switch ($this->logdest) {
            /* local syslog call, avoiding SimpleSAMLphp's wrapping */
            case 'local':
            case 'syslog':
                Assert::keyExists($this->logconfig, 'processname');
                Assert::keyExists($this->logconfig, 'facility');

                openlog($this->logconfig['processname'], LOG_PID, $this->logconfig['facility']);
                syslog(array_key_exists('priority', $this->logconfig) ? $this->logconfig['priority'] : LOG_INFO, $msg);
                break;

            /* remote syslog call via UDP */
            case 'remote':
                Assert::keyExists($this->logconfig, 'processname');
                Assert::keyExists($this->logconfig, 'facility');

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
     */
    private function generatePNhash(array &$state)
    {
        /* get a user id */
        Assert::keyExists($state, 'Attributes');

        $uid = null;
        if (array_key_exists($this->identifyingAttribute, $state['Attributes'])) {
            if (is_array($state['Attributes'][$this->identifyingAttribute])) {
                $uid = array_pop($state['Attributes'][$this->identifyingAttribute]);
            } else {
                $uid = $state['Attributes'][$this->identifyingAttribute];
            }
        }

        /* calculate a hash */
        if ($uid !== null) {
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
    private function escapeFticks(string $value): string
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
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        Assert::keyExists($config, 'federation', 'Federation identifier must be set', Error\Exception::class);
        Assert::string($config['federation'], 'Federation identifier must be a string', Error\Exception::class);
        $this->federation = $config['federation'];

        if (array_key_exists('salt', $config)) {
            Assert::string($config['salt'], 'Salt must be a string', Error\Exception::class);
            $this->salt = $config['salt'];
        } else {
            $configUtils = new Utils\Config();
            $this->salt = $configUtils->getSecretSalt();
        }

        if (array_key_exists('identifyingAttribute', $config)) {
            Assert::string($config['identifyingAttribute'], 'identifyingAttribute must be a string', Error\Exception::class);
            $this->identifyingAttribute = $config['identifyingAttribute'];
        }

        if (array_key_exists('realm', $config)) {
            Assert::string($config['realm'], 'Realm must be a string', Error\Exception::class);
            $this->realm = $config['realm'];
        }

        if (array_key_exists('algorithm', $config)) {
            if (
                is_string($config['algorithm'])
                && in_array($config['algorithm'], hash_algos())
            ) {
                $this->algorithm = $config['algorithm'];
            } else {
                throw new Error\Exception('algorithm must be a hash algorithm listed in hash_algos()');
            }
        }

        if (array_key_exists('exclude', $config)) {
            if (is_array($config['exclude'])) {
                $this->exclude = $config['exclude'];
            } elseif (is_string($config['exclude'])) {
                $this->exclude = [$config['exclude']];
            } else {
                throw new Error\Exception('F-ticks exclude must be an array');
            }
        }

        if (array_key_exists('logdest', $config)) {
            if (
                is_string($config['logdest']) &&
                in_array($config['logdest'], ['local', 'syslog', 'remote', 'stdout', 'errorlog', 'simplesamlphp'])
            ) {
                $this->logdest = $config['logdest'];
            } else {
                throw new Error\Exception(
                    'F-ticks log destination must be one of [local, remote, stdout, errorlog, simplesamlphp]'
                );
            }
        }

        /* match SSP config or we risk mucking up the openlog call */
        $globalConfig = Configuration::getInstance();
        $defaultFacility = $globalConfig->getOptionalInteger(
            'logging.facility',
            defined('LOG_LOCAL5') ? constant('LOG_LOCAL5') : LOG_USER
        );
        $defaultProcessName = $globalConfig->getOptionalString('logging.processname', 'SimpleSAMLphp');
        if (array_key_exists('logconfig', $config)) {
            if (is_array($config['logconfig'])) {
                $this->logconfig = $config['logconfig'];
            } else {
                throw new Error\Exception('F-ticks logconfig must be an array');
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
            $this->warnRiskyLogSettings($defaultFacility, $defaultProcessName);
        }
    }


    /**
     * Warn about risky logger settings
     *
     * @param int $defaultFacility
     * @param string $defaultProcessName
     * @return void
     */
    private function warnRiskyLogSettings(int $defaultFacility, string $defaultProcessName): void
    {
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


    /**
     * Process this filter
     *
     * @param  mixed &$state
     */
    public function process(array &$state): void
    {
        Assert::keyExists($state, 'Destination');
        Assert::keyExists($state['Destination'], 'entityid');
        Assert::keyExists($state, 'Source');
        Assert::keyExists($state['Source'], 'entityid');

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
            Assert::keyExists($state, 'Attributes');
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
            $fticks = array_filter($fticks, [$this, 'filterExcludedAttributes'], ARRAY_FILTER_USE_KEY);
        }

        /* assemble an F-ticks log string */
        $this->log($this->assembleFticksLogString($fticks));
    }


    /**
     * Callback method to filter excluded attributes
     *
     * @param string $attr
     * @return bool
     */
    private function filterExcludedAttributes(string $attr): bool
    {
        return !in_array($attr, $this->exclude);
    }


    /**
     * Assemble fticks log string
     *
     * @param array $fticks
     * @return string
     */
    private function assembleFticksLogString(array $fticks): string
    {
        $attributes = implode(
            '#',
            array_map(
                /**
                 * @param  string $k
                 * @param  string $v
                 * @return string
                 */
                function ($k, $v) {
                    return $k . '=' . $this->escapeFticks(strval($v));
                },
                array_keys($fticks),
                $fticks
            )
        );

        return sprintf('F-TICKS/%s/%s#%s#', $this->federation, self::$fticksVersion, $attributes);
    }
}
