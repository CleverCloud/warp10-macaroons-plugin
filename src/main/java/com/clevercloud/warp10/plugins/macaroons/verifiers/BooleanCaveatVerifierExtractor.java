package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.clevercloud.warp10.plugins.macaroons.CaveatDataExtractor;
import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;

public class BooleanCaveatVerifierExtractor implements GeneralCaveatVerifier, CaveatDataExtractor<Boolean> {
    public final String CAVEAT_PREFIX;

    private Boolean current_value;

    public BooleanCaveatVerifierExtractor(String prefix) {
        CAVEAT_PREFIX = prefix;
        current_value = null;
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        if (caveat.startsWith(CAVEAT_PREFIX)) {
            Boolean bcaveat = Boolean.parseBoolean(caveat.substring(CAVEAT_PREFIX.length()));
            if (current_value == null) {
                current_value = bcaveat;
            } else {
                current_value = current_value && bcaveat;
            }
            return true;
        }
        return false;
    }

    @Override
    public Boolean getData() {
        return current_value;
    }

    @Override
    public String getCaveatPrefix() {
        return CAVEAT_PREFIX;
    }
}
