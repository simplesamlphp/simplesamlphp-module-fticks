# fticks:Fticks

![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-fticks/workflows/CI/badge.svg?branch=master)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-fticks/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-fticks)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-fticks/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-fticks/?branch=master)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-fticks/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-fticks)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-fticks/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-fticks)

Log statistics in the [F-ticks federation log format](https://wiki.geant.org/display/gn42jra3/F-ticks+standard).

## Installation

Once you have installed SimpleSAMLphp, installing this module is
very simple.  Just execute the following command in the root of your
SimpleSAMLphp installation:

```bash
vendor/bin/composer require simplesamlphp/simplesamlphp-module-fticks:dev-master
```

where `dev-master` instructs Composer to install the `master` (**development**)
branch from the Git repository. See the
[releases](https://github.com/simplesamlphp/simplesamlphp-module-fticks/releases)
available if you want to use a stable version of the module.

## Configuration

Next thing you need to do is to enable the module: in `config.php`,
search for the `module.enable` key and set `fticks` to true:

```php
    'module.enable' => [
        'fticks' => true,
        …
    ],
```

For configuration of the module, see [docs/authproc_fticks.md][1].

[1]: https://github.com/simplesamlphp/simplesamlphp-module-fticks/blob/master/docs/authproc_fticks.md

### Acknowledgements

Some work on making SimpleSAMLphp log in F-ticks format was done by NIIF, and
is available at [NIIF][2].
This module may derive ideas from their work.

[2]: https://github.com/NIIF/simplesamlphp-module-ftickslogger

Likewise, some ideas came from the [Shibboleth IdP's F-ticks implementation][3]
and some of the config options should look familiar to Shibboleth users.

[3]: https://wiki.shibboleth.net/confluence/display/IDP30/FTICKSLoggingConfiguration
