package com.clevercloud.warp10.plugins.macaroons;

public class MacaroonPluginConfig {

    /**
     * String
     * Value of the secret root for signing macaroon
     */
    public static final String MACAROON_SECRET = "plugins.macaroons.secret";

    /**
     * String
     * Value of warp10 token prefix triggering the plugin use, default to macaroon:
     */
    public static final String MACAROON_TOKEN_PREFIX = "plugins.macaroons.token_prefix";

    /**
     * String
     * Sometimes, it is useful, for macaroons shared on multiples services, to be able to prefix caveat, this is the prefix value
     */
    public static final String MACAROON_WARP_CAVEAT_PREFIX = "plugins.macaroons.warp_caveat_prefix";

    /**
     * List<String> put every regexp separated with a coma (,)
     * Sometimes, it is useful, for macaroons shared on multiples services, to be able to automatically valid some caveat because it's useless for warp10, this will allow to add a list of regexp to auto valid caveat
     */
    public static final String MACAROON_VALID_CAVEAT_REGEXP = "plugins.macaroons.valid_caveats.regexps";

}
