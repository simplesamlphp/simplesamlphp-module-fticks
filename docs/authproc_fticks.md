# `fticks:Fticks`

Log statistics in the [F-ticks federation log format][1].

[1]: https://wiki.geant.org/display/gn42jra3/F-ticks+standard

The filter aims to produce as many F-ticks attributes as possible, irrespective
of whether SimpleSAMLphp is acting as an identity provider or a
SAML service provider.

## Configuration

The filter supports the following configuration options:

`federation`
:   F-ticks federation identifier. Specifying a federation identifier is
    **mandatory**, and the filter will generate an exception if one is not
    given.

`salt`
:   A salt used to preserve the privacy of the F-ticks _PN_ attribute.
    If not specified, the `secretsalt` from the main config is used.

`identifyingAttribute`
:   The SAML attribute specifying the user id. It is **mandatory**

`realm`
:   The SAML attribute specifying the user's realm. If not specified,
    the F-ticks _REALM_ attribute is not generated.

`algorithm`
:   The hash algorithm to use. Defaults to `sha256`, but any algorithm
    [supported by PHP](http://php.net/manual/en/function.hash-algos.php)
    can be used.

`pnHashIsTargeted`
:   When generating the F-Ticks _PN_ attribute, include the source or
    destination entityId to create a targeted version of the subject. Must
    be one of the following options:

> * `none` - _PN_ depends only on the `federation` and
    `identifyingAttribute` (this is the default, and compatible with
    other implementations).
> * `source` - _PN_ is targeted based on the SAML source. This is useful
    for [bridging configurations](bridging) where the `identifyingAttribute`
    may not be unique.
> * `destination` - _PN_ is targeted based on the SAML destination
> * `both` - _PN_ is targeted based on both the SAML source and destination
    (this option exists to preserve backwards-compatibility, and may
    lead to overcounting of subjects).

[bridging]: https://simplesamlphp.org/docs/stable/simplesamlphp-advancedfeatures.html#bridging-between-protocols

`exclude`
:   An array of F-ticks attributes to exclude/filter from the output.

`logdest`
:   Destination for F-ticks logs. Must be one of the following options:

> * `simplesamlphp` - use SimpleSAMLphp's built-in logging mechanism
    (this is the default).
> * `local` - log using the PHP [syslog][2] functions, potentially
    avoiding some of the extra information SimpleSAMLphp includes in logs.
> * `remote` - log to a remote RFC 5424 syslog server using UDP.
> * `errorlog` - log using PHP's [error_log][3] function, probably
    into the web server logs.
> * `stdout` - write to standard out, primarily for debugging.

[2]: https://php.net/manual/en/function.syslog.php
[3]: https://php.net/manual/en/function.error-log.php

`logconfig`
:   An array of configuration options for the logging method. The exact values
    supported depend on the specific `logdest`, but the following are
    understood:

> * `priority` - the syslog priority or severity as a PHP constant,
                 defaulting to `LOG_INFO`. _[local, remote]_
> * `facility` - the syslog facility, defaulting to `logging.facility`
                 from the main config. _[local, remote]_
> * `processname` - the syslog process name, defaulting to
                    `logging.processname` from the main config.
                    _[local, remote]_
> * `host` - the hostname of the remote syslog server,
             defaulting to `localhost`. _[remote]_
> * `port` - the port of the remote syslog server,
             defaulting to `514`. _[remote]_

Note that if `logdest` is `local` and you set either `processname` or `facility`
to a value that's different to what is in SimpleSAMLphp's global config, you may
end up with inconsistent output from SimpleSAMLphp's own logging. This is
because PHP's [openlog](http://php.net/manual/en/function.openlog.php) function
does not return a handle.

### Examples

In its simplest form, the filter is configured like this:

```php
    'authproc' => [
        50 => [
            'class' => 'fticks:Fticks',
            'federation' => 'ACME',
        ],
    ],
```

A more complete example looks like:

```php
    'authproc' => [
        50 => [
            'class' => 'fticks:Fticks',
            'federation' => 'ACME',
            'salt' => 'someVerySecretStringDifferentFromTheDefault',
            'identifyingAttribute' => 'eduPersonPrincipalName',
            'realm' => 'schacHomeOrganization',
            'algorithm' => 'sha512',
            'exclude' => ['PN'],
        ],
    ],
```

Remote logging can be done like this:

```php
    'authproc' => [
        50 => a[
            'class' => 'fticks:Fticks',
            'federation' => 'ACME',
            'logdest' => 'remote',
            'logconfig' => [
                'host' => '90.147.166.156',
                'port' => 514,
            ],
        ],
    ],
```

## F-ticks output

The filter is capable of generating the following F-ticks attributes:
AP, AM, CSI, PN, REALM, RESULT, RP, TS.

The following notes document how some of these attributes are
generated/derived:

`AM`
:   The authentication method is derived from the SP's SAML state. If
    that is not available, is set to
    `urn:oasis:names:tc:SAML:2.0:ac:classes:Password` when one of the
    authentication sources based on the [UserPassBase][4] class.

[4]: https://github.com/simplesamlphp/simplesamlphp/blob/master/modules/core/lib/Auth/UserPassBase.php

`CSI`
:   The calling station identifier is set to the SimpleSAMLphp tracking
    id (same as logs)

`PN`
:   The PN is generated in a similar way too, but completely independently from
    a [saml:PersistentNameID][5]. Depends on the setting of `pnHashIsTargeted`.

[5]: https://simplesamlphp.org/docs/stable/saml:nameid

`RESULT`
:   Result is always set to `OK`, since if the authentication fails,
    the authproc filter is never called.

`TS`
:   The timestamp is set to the SAML AuthNInstant if that is known,
    or the current time otherwise.
