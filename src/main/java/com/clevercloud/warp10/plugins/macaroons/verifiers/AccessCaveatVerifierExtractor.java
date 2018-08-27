package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.clevercloud.warp10.plugins.macaroons.CaveatDataExtractor;
import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
import com.google.common.collect.Sets;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class AccessCaveatVerifierExtractor implements GeneralCaveatVerifier, CaveatDataExtractor<Set<String>> {
    public final String CAVEAT_PREFIX;

    private Set<String> accesses;

    private Set<String> needed_access;

    public AccessCaveatVerifierExtractor(String prefix, Set<String> requiredAccess) {
        CAVEAT_PREFIX = prefix;
        accesses = null;
        needed_access = requiredAccess;
    }

    public AccessCaveatVerifierExtractor(String... requiredAccesses){
        this("access = ", new HashSet<String>(Arrays.asList(requiredAccesses)));
    }

    public AccessCaveatVerifierExtractor(String requiredAccess){
        this(new String[]{requiredAccess});
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        if(caveat.startsWith(CAVEAT_PREFIX)){
            HashSet<String> cavaetAuthorities = asTrimmedSet(caveat.substring(CAVEAT_PREFIX.length()).split("[,]"));
            if(accesses == null){
                accesses = cavaetAuthorities;
            }else {
                accesses = Sets.intersection(accesses, cavaetAuthorities);
            }
            return accesses.containsAll(needed_access);
        }
        return false;
    }

    private HashSet<String> asTrimmedSet(String[] cavaetAuthorities) {
        HashSet<String> result = new HashSet<>( cavaetAuthorities.length );
        for (String cavaetAuthority : cavaetAuthorities) {
            result.add(cavaetAuthority.trim());
        }
        return result;
    }

    @Override
    public Set<String> getData() {
        return accesses;
    }

    @Override
    public String getCaveatPrefix() {
        return CAVEAT_PREFIX;
    }
}
