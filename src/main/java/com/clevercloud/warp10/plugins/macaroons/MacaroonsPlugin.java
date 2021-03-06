package com.clevercloud.warp10.plugins.macaroons;
//
//   Copyright 2018  Clever Cloud
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;

import com.clevercloud.warp10.plugins.macaroons.verifiers.*;
import io.warp10.WarpConfig;
import io.warp10.continuum.AuthenticationPlugin;
import io.warp10.continuum.Tokens;
import io.warp10.quasar.token.thrift.data.ReadToken;
import io.warp10.quasar.token.thrift.data.WriteToken;
import io.warp10.script.WarpScriptException;
import io.warp10.warp.sdk.AbstractWarp10Plugin;
import com.github.nitram509.jmacaroons.Macaroon;
import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.*;

/**
 * Example Warp 10 plugin which adds an AuthenticationPlugin to support a dummy
 * token type prefixed by 'dummy:'
 * <p>
 * The plugin is added by adding the following configuration:
 * <p>
 * warp10.plugin.authexample = io.warp10.plugins.authexample.AuthExampleWarp10Plugin
 */
public class MacaroonsPlugin extends AbstractWarp10Plugin implements AuthenticationPlugin {
    //public class MacaroonsPlugin {
    private static String PREFIX;

    private static final Logger LOG = LoggerFactory.getLogger(MacaroonsPlugin.class);

    // Configuration
    private String secretKey;
    private String warp_caveat_prefix;
    private Set<String> auto_valid_caveat_regexp;
    private Set<Pattern> auto_valid_caveat_regexp_compiled;


    private MacarronsVerifierExtractor getCommonVerifierForMacaroon(Macaroon macaroon) {
        MacarronsVerifierExtractor mve = new MacarronsVerifierExtractor(macaroon)
                .satisfyGeneralAndExtract(new TimestampCaveatVerifierExtractor())
                .satisfyGeneralAndExtract(new MapCaveatVerifierExtractor(warp_caveat_prefix + "label = "))
                .satisfyGeneralAndExtract(new MapCaveatVerifierExtractor(warp_caveat_prefix + "attr = "))
                .satisfyGeneralAndExtract(new StringCaveatVerifierExtractor(warp_caveat_prefix + "appname = "))
                .satisfyGeneralAndExtract(new StringCaveatVerifierExtractor("producer = "))
                .satisfyGeneralAndExtract(new StringSetCaveatVerifierExtractor(warp_caveat_prefix + "producers = "))
                .satisfyGeneralAndExtract(new StringSetCaveatVerifierExtractor(warp_caveat_prefix + "apps = "))
                .satisfyGeneralAndExtract(new StringCaveatVerifierExtractor("owner = "))
                .satisfyGeneralAndExtract(new StringSetCaveatVerifierExtractor(warp_caveat_prefix + "owners = "));

        if (!auto_valid_caveat_regexp_compiled.isEmpty()) {
            mve = mve.satisfyGeneral(new RegexpCaveatVerifier(auto_valid_caveat_regexp_compiled));
        }
        return mve;
    }

    private Macaroon getMacaroonFromToken(String token) {
        return MacaroonsBuilder.deserialize(token.substring(PREFIX.length()).trim());
    }

    private class CommonMacaroonInfos {
        public final Long timestamp;
        public final Map<String, String> labels;
        public final Map<String, String> attributes;
        public final String appName;


        private CommonMacaroonInfos(Long timestamp, Map<String, String> labels, Map<String, String> attributes, String appName) {
            this.timestamp = timestamp;
            this.labels = labels;
            this.attributes = attributes;
            this.appName = appName;
        }
    }

    private CommonMacaroonInfos extractCommonInfosFromMacaroon(Macaroon macaroon, MacarronsVerifierExtractor mve) {
        CaveatDataExtractor<Date> timeExtractor = mve.getExtractorForPrefix(warp_caveat_prefix + "time < ");
        CaveatDataExtractor<Map<String, String>> labelExtractor = mve.getExtractorForPrefix(warp_caveat_prefix + "label = ");
        CaveatDataExtractor<Map<String, String>> attributesExtractor = mve.getExtractorForPrefix(warp_caveat_prefix + "attr = ");
        CaveatDataExtractor<String> appNameExtractor = mve.getExtractorForPrefix(warp_caveat_prefix + "appname = ");

        return new CommonMacaroonInfos(
                (timeExtractor.getData() != null ? timeExtractor.getData().toInstant().toEpochMilli() : null),
                labelExtractor.getData() != null ? labelExtractor.getData() : new HashMap<>(),
                attributesExtractor.getData() != null ? attributesExtractor.getData() : new HashMap<>(),
                appNameExtractor.getData()
        );
    }

    //@Override
    public ReadToken extractReadToken(String token) throws WarpScriptException {
        if (!token.startsWith(PREFIX)) {
            return null;
        }

        Macaroon macaroon = getMacaroonFromToken(token);

        MacarronsVerifierExtractor verifier = getCommonVerifierForMacaroon(macaroon)
                .satisfyGeneralAndExtract(new StringCaveatVerifierExtractor("billedid = "))
                .satisfyGeneralAndExtract(new AccessCaveatVerifierExtractor(warp_caveat_prefix + "access = ", "READ"));


        boolean valid = verifier.isValid(secretKey);

        if (!verifier.isValid(secretKey)) {
            return null;
        }

        ReadToken rtoken = new ReadToken();

        CommonMacaroonInfos common = extractCommonInfosFromMacaroon(macaroon, verifier);

        rtoken.setLabels(common.labels);
        rtoken.setAttributes(common.attributes);

        if (common.timestamp != null) {
            rtoken.setExpiryTimestamp(common.timestamp);
        }

        if (common.appName != null) {
            rtoken.setAppName(common.appName);
        }

        CaveatDataExtractor<Set<String>> producersExtractor = verifier.getExtractorForPrefix("producers = ");
        if(producersExtractor.getData() != null) {
            rtoken.setProducers(
                    producersExtractor.getData()
                            .stream()
                            .map(p -> ByteBuffer.wrap(p.getBytes()))
                            .collect(Collectors.toList())
            );
        }

        CaveatDataExtractor<Set<String>> appsExtractor = verifier.getExtractorForPrefix("apps = ");
        if(appsExtractor.getData() != null) {
            rtoken.setApps(new ArrayList<>(appsExtractor.getData()));
        }

        CaveatDataExtractor<Set<String>> ownersExtractor = verifier.getExtractorForPrefix("owners = ");
        if(ownersExtractor.getData() != null) {
            rtoken.setOwners(
                    ownersExtractor.getData()
                            .stream()
                            .map(o -> ByteBuffer.wrap(o.getBytes()))
                            .collect(Collectors.toList())
            );
        }

        CaveatDataExtractor<String> billedIdExtractor = verifier.getExtractorForPrefix("billedid = ");
        if(billedIdExtractor.getData() != null) {
            rtoken.setBilledId(billedIdExtractor.getData().getBytes());
        }

        return rtoken;
    }

    //@Override
    public WriteToken extractWriteToken(String token) throws WarpScriptException {
        if (!token.startsWith(PREFIX)) {
            return null;
        }
        Macaroon macaroon = getMacaroonFromToken(token);

        MacarronsVerifierExtractor verifier = getCommonVerifierForMacaroon(macaroon)
                .satisfyGeneralAndExtract(new AccessCaveatVerifierExtractor(warp_caveat_prefix + "access = ", "WRITE"));

        boolean valid = verifier.isValid(secretKey);

        if (!verifier.isValid(secretKey)) {
            return null;
        }

        WriteToken wtoken = new WriteToken();

        CommonMacaroonInfos common = extractCommonInfosFromMacaroon(macaroon, verifier);

        wtoken.setLabels(common.labels);
        wtoken.setAttributes(common.attributes);

        if (common.timestamp != null) {
            wtoken.setExpiryTimestamp(common.timestamp);
        }

        if (common.appName != null) {
            wtoken.setAppName(common.appName);
        }

        CaveatDataExtractor<String> producerExtractor = verifier.getExtractorForPrefix("producer = ");
        if(producerExtractor.getData() != null) {
            wtoken.setProducerId(producerExtractor.getData().getBytes());
        }

        CaveatDataExtractor<String> ownerExtractor = verifier.getExtractorForPrefix("owner = ");
        if(ownerExtractor.getData() != null) {
            wtoken.setOwnerId(ownerExtractor.getData().getBytes());
        }

        return wtoken;
    }

    //@Override
    public void init(Properties properties) {
        LOG.info("Reading Macaroons plugin configuration");
        readConfig();
        LOG.info("Registering Macaroon authentication plugin");
        Tokens.register(this);
    }

    public void readConfig() {
        Properties props = WarpConfig.getProperties();
        if (props.containsKey(MacaroonPluginConfig.MACAROON_SECRET)) {
            secretKey = props.getProperty(MacaroonPluginConfig.MACAROON_SECRET);
        } else {
            LOG.error("No secret defined for Macaroon plugin, it will not work and it's dangerous, please add " + MacaroonPluginConfig.MACAROON_SECRET + " entry to your configuration");
        }

        PREFIX = props.getProperty(MacaroonPluginConfig.MACAROON_TOKEN_PREFIX, "macaroon:");

        if (props.containsKey(MacaroonPluginConfig.MACAROON_WARP_CAVEAT_PREFIX)) {
            warp_caveat_prefix = props.getProperty(MacaroonPluginConfig.MACAROON_WARP_CAVEAT_PREFIX);
            LOG.info("Macaroon plugin will use " + warp_caveat_prefix + " as a prefix for all caveat");
        } else {
            warp_caveat_prefix = "";
        }

        if (props.containsKey(MacaroonPluginConfig.MACAROON_VALID_CAVEAT_REGEXP)) {
            auto_valid_caveat_regexp = Arrays.asList(props.getProperty(MacaroonPluginConfig.MACAROON_VALID_CAVEAT_REGEXP).split(","))
                    .stream()
                    .map(s -> s.trim())
                    .collect(Collectors.toSet());
            auto_valid_caveat_regexp_compiled = auto_valid_caveat_regexp
                    .stream()
                    .map(s -> Pattern.compile(s))
                    .collect(Collectors.toSet());
            LOG.info("Macaroon plugin will automatically validate every caveat with theses regexp: " + auto_valid_caveat_regexp);
        } else {
            auto_valid_caveat_regexp = new HashSet<>();
            auto_valid_caveat_regexp_compiled = new HashSet<>();
        }
    }


    public String getPrefix() {
        return PREFIX;
    }
}
