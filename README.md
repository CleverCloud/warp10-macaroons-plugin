# Warp10 Macaroons auth plugin

This plugin adds macaroons support to warp10. Instead of using `Read` or `Write` tokens crafted with Worf,
it allows you to directly use macaroons.

# Install

TODO

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


    signature 3f1fd7d14bf9b902f69fdaa0c98879c0bb1b174e70b572527aefea524c33b352
```



# Plugin configuration

Configuration keys for the plugin is to add to the warp10.conf file.
All options are listed and described in the MacaroonPluginConfig.java file

```
plugins.macaroons.secret = test secret key

```
