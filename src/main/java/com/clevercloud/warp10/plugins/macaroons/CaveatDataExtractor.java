package com.clevercloud.warp10.plugins.macaroons;

import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;

public interface CaveatDataExtractor<T> extends GeneralCaveatVerifier {

    public T getData();

    public String getCaveatPrefix();
}
