package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

public class RegexpCaveatVerifier implements GeneralCaveatVerifier {

    private Set<Pattern> validation_regexp;

    public RegexpCaveatVerifier(Set<Pattern> validation_regexp) {
        this.validation_regexp = validation_regexp;
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        return validation_regexp
                .stream()
                .reduce(
                        validation_regexp.isEmpty(),
                        (sum, patter) -> (patter.matcher(caveat).find() || sum),
                        (a, b) -> a && b
                );
    }
}
