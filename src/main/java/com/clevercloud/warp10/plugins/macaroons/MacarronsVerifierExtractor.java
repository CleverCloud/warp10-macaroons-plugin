package com.clevercloud.warp10.plugins.macaroons;

import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
import com.github.nitram509.jmacaroons.Macaroon;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MacarronsVerifierExtractor extends MacaroonsVerifier {

    private Map<String, CaveatDataExtractor> caveatDataExtractors;

    public MacarronsVerifierExtractor(Macaroon macaroon) {
        super(macaroon);
        caveatDataExtractors = new HashMap<>();
    }

    public MacarronsVerifierExtractor satisfyGeneralAndExtract(CaveatDataExtractor verifier) {
        caveatDataExtractors.put(verifier.getCaveatPrefix(), verifier);
        super.satisfyGeneral(verifier);
        return this;
    }

    public CaveatDataExtractor getExtractorForPrefix(String prefix){
        return caveatDataExtractors.get(prefix);
    }

    public MacarronsVerifierExtractor satisfyGeneral(GeneralCaveatVerifier verifier) {
        super.satisfyGeneral(verifier);
        return this;
    }
}
