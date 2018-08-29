package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.clevercloud.warp10.plugins.macaroons.CaveatDataExtractor;
import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
import com.google.common.collect.Sets;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class MaxLongCaveatVerifierExtractor implements GeneralCaveatVerifier, CaveatDataExtractor<Long> {
    public final String CAVEAT_PREFIX;

    private Long current_value;

    public MaxLongCaveatVerifierExtractor(String prefix) {
        CAVEAT_PREFIX = prefix;
        current_value = null;
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        if (caveat.startsWith(CAVEAT_PREFIX)) {
            Long lcaveat = Long.parseLong(caveat.substring(CAVEAT_PREFIX.length()));
            if (current_value == null) {
                current_value = lcaveat;
            } else {
                if (current_value > lcaveat) {
                    current_value = lcaveat;
                }
            }
            return true;
        }
        return false;
    }

    @Override
    public Long getData() {
        return current_value;
    }

    @Override
    public String getCaveatPrefix() {
        return CAVEAT_PREFIX;
    }
}
