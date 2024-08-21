# Upgrade notes for simplesamlphp-module-fticks

## Change in PN generation

The `PN` F-Ticks attribute is defined as "A unique identifier for the
subject involved in the event." To allow statistics to be aggregated,
this is commonly implemented as a privacy-preserving hash, and
simplesamlphp-module-fticks is no different.

To ensure uniqueness in multiple identity provider (bridge)
configurations, simplesamlphp-module-fticks originally
scoped the generation of the `PN` hash in the same way as the
[saml:PersistentNameID](https://simplesamlphp.org/docs/stable/saml/nameid.html).
Unfortunately, in deriving the hashing algorithm, earlier versions
of this module erroneously included both the source and the
destination entityId in the calculation of the hash. Where the
same user logs into several different services, a new PN hash is
generated for each service. This may result in an overinflation
in the number of unique principals. This behaviour is compatible
with the definition but is different to the way e.g.
[Shibboleth IdP](https://wiki.shibboleth.net/confluence/display/IDP30/FTICKSLoggingConfiguration)
computes a hash, and may not be what aggregators expect.

In order to align the statistics generation with other software, the
default behaviour has been changed to create a PN hash that only depends
on the `identitfyingAttribute` and the `federation`.

People with existing statistics who wish to retain the old behaviour
should set the `pnHashIsTargeted` option to `both`.

People using bridges where the `identitfyingAttribute` cannot be
guarenteed unique should set the `pnHashIsTargeted` option to `source`.
