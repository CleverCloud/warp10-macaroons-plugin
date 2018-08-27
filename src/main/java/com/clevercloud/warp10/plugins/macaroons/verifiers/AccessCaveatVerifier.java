package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
import com.google.common.collect.Sets;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AccessCaveatVerifier implements GeneralCaveatVerifier {
    public final String CAVEAT_PREFIX;

    private Set<String> accesses;

    private Set<String> needed_access;

    public AccessCaveatVerifier(Set<String> requiredAccess) {
        CAVEAT_PREFIX = "access = ";
        accesses = null;
        needed_access = requiredAccess;
    }

    public AccessCaveatVerifier(String... requiredAccesses){
        this(new HashSet<String>(Arrays.asList(requiredAccesses)));
    }

    public AccessCaveatVerifier(String requiredAccess){
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
                System.out.println("UNION: "+accesses.toString());
            }
            System.out.println("caveat:+" + caveat + "  |  " + "accesses:" + accesses.toString() + "  |  " + "cavaetAuthorities:"+cavaetAuthorities.toString());

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
}
