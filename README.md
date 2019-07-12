fticks:Fticks
=============
[![Build Status](https://travis-ci.org/simplesamlphp/simplesamlphp-module-fticks.svg?branch=master)](https://travis-ci.org/simplesamlphp/simplesamlphp-module-fticks)

Log statistics in the [F-ticks federation log format](https://wiki.geant.org/display/gn42jra3/F-ticks+standard).

Installation
------------

Once you have installed SimpleSAMLphp, installing this module is
very simple.  Just execute the following command in the root of your
SimpleSAMLphp installation:

```
composer.phar require simplesamlphp/simplesamlphp-module-fticks:dev-master
```

where `dev-master` instructs Composer to install the `master` (**development**)
branch from the Git repository. See the
[releases](https://github.com/simplesamlphp/simplesamlphp-module-fticks/releases)
available if you want to use a stable version of the module.

Documentation
-------------

See [docs/authproc_fticks.md](https://github.com/simplesamlphp/simplesamlphp-module-fticks/blob/master/docs/authproc_fticks.md).

Acknowledgements
----------------

Some work on making SimpleSAMLphp log in F-ticks format was done by NIIF, and is available at [NIIF/simplesamlphp-module-ftickslogger](https://github.com/NIIF/simplesamlphp-module-ftickslogger). This module may derive ideas from their work.

Likewise, some ideas came from the [Shibboleth IdP's F-ticks implimentation](https://wiki.shibboleth.net/confluence/display/IDP30/FTICKSLoggingConfiguration), and some of the config options should look familiar to Shibboleth users.

