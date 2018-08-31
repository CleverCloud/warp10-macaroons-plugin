package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.clevercloud.warp10.plugins.macaroons.CaveatDataExtractor;
import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
import com.google.common.collect.Sets;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class StringSetCaveatVerifierExtractor implements GeneralCaveatVerifier, CaveatDataExtractor<Set<String>> {
    public final String CAVEAT_PREFIX;

    private Set<String> stringset;


    public StringSetCaveatVerifierExtractor(String prefix) {
        CAVEAT_PREFIX = prefix;
        stringset = null;
    }

    public Set<String> extractCaveatSetAndUpdateState (String caveat){
        if (caveat.startsWith(CAVEAT_PREFIX)) {
            HashSet<String> cavaet_string_set = asTrimmedSet(caveat.substring(CAVEAT_PREFIX.length()).split("[,]"));
            if (stringset == null) {
                stringset = cavaet_string_set;
            } else {
                stringset = Sets.intersection(stringset, cavaet_string_set);
            }
            return stringset;
        }
        return null;
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        return extractCaveatSetAndUpdateState(caveat) != null;
    }

    private HashSet<String> asTrimmedSet(String[] cavaetAuthorities) {
        HashSet<String> result = new HashSet<>(cavaetAuthorities.length);
        for (String cavaetAuthority : cavaetAuthorities) {
            result.add(cavaetAuthority.trim());
        }
        return result;
    }

    @Override
    public Set<String> getData() {
        return stringset;
    }

    @Override
    public String getCaveatPrefix() {
        return CAVEAT_PREFIX;
    }
}
