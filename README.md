# Warp10 Macaroons auth plugin

This plugin adds macaroons support to warp10. Instead of using `Read` or `Write` tokens crafted with Worf,
it allows you to directly use macaroons.

# Install

TODO (Waiting for the warp10 plugin model to be released). But shortly, compile this project with gradle shadowjar, put the jar on the warp10 classpath, and add the plugin: warp10.plugins = com.clevercloud.warp10.plugins.macaroons.MacaroonsPlugin
 There is a eay way to test your macaroon with the warpScript AUTHINFO keywork, but it's not made to do WRITE&READ token, as mention here https://github.com/cityzendata/warp10-platform/pull/274
 

# Macaroon format

```
    location TODO
    identifier TODO

    # How to:
    # What is the macaroon -> token translation (how it react on sub-macaroon)

    # Token expiration (date can only be more recent on next macaroon)
    cid time < 2020-01-01T00:00

    # Token access read and/or write (you can only remove access)
    cid access = READ, WRITE

    # Labels (you can only add new labels, unable to change value)
    cid label = labelkey1=labelvalue1
    cid label = labelkey2=labelvalue2
    cid label = labelkey3=labelvalue3

    # Attributes (you can only add new attributes, unable to change value)
    cid attr = attributekey1=attributevalue1
    cid attr = attributekey2=attributevalue2
    cid attr = attributekey3=attributevalue3

    # Write token only, App Name (cannot be set a second time, only once)
    appname = ljksjksdqhkl

    # Read token only, Apps id (String array, values can disappear but not be added)
    apps = app1, app2, app3

    # Read Token Producers (String array, values can disappear but not be added)
    producers = prod1, prod2, prod3

    # Write Token Producer (String, can't be changed)
    producer = prod1

    # Read Token Owners (String array, values can disappear but not be added)
    owners = owner1, owner2, owner3

    # Write Token Owner (String, can't be changed)
    owner = ownerA

    # Read Token, billed ID (String, can't be changed)
    billedid = myBillingId

    signature 3f1fd7d14bf9b902f69fdaa0c98879c0bb1b174e70b572527aefea524c33b352
```

This plugin do not use macaroon identifier and location, because nothing to map easily to a warp10 token. You can use it on your management.


# Plugin configuration

Configuration keys for the plugin is to add to the warp10.conf file.
All options are listed and described in the src/main/java/com/clevercloud/warp10/plugins/macaroons/MacaroonPluginConfig.java file

```
plugins.macaroons.secret = test secret key

```
Current options include secret, token prefix filter, caveat prefix and auto validation caveat management.