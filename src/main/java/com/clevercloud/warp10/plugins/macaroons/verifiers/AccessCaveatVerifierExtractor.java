package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.clevercloud.warp10.plugins.macaroons.CaveatDataExtractor;
import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
import com.google.common.collect.Sets;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class AccessCaveatVerifierExtractor extends StringSetCaveatVerifierExtractor {

    private Set<String> needed_access;

    public AccessCaveatVerifierExtractor(String prefix, Set<String> requiredAccess) {
        super(prefix);
        needed_access = requiredAccess;
    }

    public AccessCaveatVerifierExtractor(String... requiredAccesses) {
        this("access = ", new HashSet<String>(Arrays.asList(requiredAccesses)));
    }

    public AccessCaveatVerifierExtractor(String prefix, String... requiredAccesses) {
        this(prefix, new HashSet<String>(Arrays.asList(requiredAccesses)));
    }

    public AccessCaveatVerifierExtractor(String prefix, String requiredAccess) {
        this(prefix, new String[]{requiredAccess});
    }

    public AccessCaveatVerifierExtractor(String requiredAccess) {
        this(new String[]{requiredAccess});
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        Set<String> caccess = extractCaveatSetAndUpdateState(caveat);
        return caccess != null ? caccess.containsAll(needed_access) : false;
    }


}
