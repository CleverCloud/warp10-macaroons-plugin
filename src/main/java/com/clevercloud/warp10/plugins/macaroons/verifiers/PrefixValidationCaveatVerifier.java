package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;

public class PrefixValidationCaveatVerifier implements GeneralCaveatVerifier {

    public final String CAVEAT_PREFIX;

    public PrefixValidationCaveatVerifier(String caveat_prefix) {
        CAVEAT_PREFIX = caveat_prefix;
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        if (caveat.startsWith(CAVEAT_PREFIX)) {
            return true;
        }
        return false;
    }
}
