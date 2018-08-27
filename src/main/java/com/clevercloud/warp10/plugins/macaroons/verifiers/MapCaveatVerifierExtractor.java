package com.clevercloud.warp10.plugins.macaroons.verifiers;

import com.clevercloud.warp10.plugins.macaroons.CaveatDataExtractor;
import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;

import java.util.HashMap;
import java.util.Map;

public class MapCaveatVerifierExtractor implements GeneralCaveatVerifier, CaveatDataExtractor<Map<String, String>> {

    public final String CAVEAT_PREFIX;

    private Map<String,String> datas = new HashMap<>();


    public MapCaveatVerifierExtractor(String caveat_prefix) {
        CAVEAT_PREFIX = caveat_prefix;
    }

    @Override
    public boolean verifyCaveat(String caveat) {
        if (caveat.startsWith(CAVEAT_PREFIX)) {
            String line = caveat.substring(CAVEAT_PREFIX.length());
            int whereIsEqual = line.indexOf("=");
            String k = line.substring(0,whereIsEqual).trim();
            String v = line.substring(whereIsEqual+1).trim();
            datas.putIfAbsent(k,v);
            return true;
        }
        return false;
    }

    @Override
    public Map<String, String> getData() {
        return datas;
    }

    @Override
    public String getCaveatPrefix() {
        return CAVEAT_PREFIX;
    }
}
