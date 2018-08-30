package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.clevercloud.warp10.plugins.macaroons.CaveatDataExtractor;
import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;

import java.util.Random;

public class StringCaveatVerifierExtractor implements GeneralCaveatVerifier, CaveatDataExtractor<String> {
    public final String CAVEAT_PREFIX;

    private String current_value;

 //   private Double r;

    public StringCaveatVerifierExtractor(String prefix) {
        CAVEAT_PREFIX = prefix;
        current_value = null;
//        r = Math.random();
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        boolean b = false;
        if (caveat.startsWith(CAVEAT_PREFIX)) {
            String lcaveat = caveat.substring(CAVEAT_PREFIX.length());
            if (current_value == null) {
                current_value = lcaveat;
                b = true;
            } else {
                b = current_value.equals(lcaveat);
            }
        }
//        System.out.println(r.toString()+" "+caveat + "   :   " + current_value + " " + b);

        return b;
    }

    @Override
    public String getData() {
        return current_value;
    }

    @Override
    public String getCaveatPrefix() {
        return CAVEAT_PREFIX;
    }
}
