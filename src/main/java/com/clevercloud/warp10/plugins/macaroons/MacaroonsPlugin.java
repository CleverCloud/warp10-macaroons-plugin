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
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.regex.*;

/**
 * Example Warp 10 plugin which adds an AuthenticationPlugin to support a dummy
 * token type prefixed by 'dummy:'
 * 
 * The plugin is added by adding the following configuration:
 * 
 * warp10.plugin.authexample = io.warp10.plugins.authexample.AuthExampleWarp10Plugin
 * 
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


  private MacarronsVerifierExtractor getCommonVerifierForMacaroon(Macaroon macaroon ){
    MacarronsVerifierExtractor mve = new MacarronsVerifierExtractor(macaroon)
            .satisfyGeneralAndExtract(new TimestampCaveatVerifierExtractor())
            .satisfyGeneralAndExtract(new MapCaveatVerifierExtractor(warp_caveat_prefix+"label = "))
            .satisfyGeneralAndExtract(new MapCaveatVerifierExtractor(warp_caveat_prefix+"attr = "))
            .satisfyGeneralAndExtract(new BooleanCaveatVerifierExtractor(warp_caveat_prefix+"lookup = "));
    if(!auto_valid_caveat_regexp_compiled.isEmpty()){
      mve = mve.satisfyGeneral(new RegexpCaveatVerifier(auto_valid_caveat_regexp_compiled));
    }
    return mve;
  }

  private Macaroon getMacaroonFromToken(String token){
    return MacaroonsBuilder.deserialize(token.substring(PREFIX.length()).trim());
  }

  private class CommonMacaroonInfos {
    public final Long timestamp;
    public final Map<String,String> labels;
    public final Map<String,String> attributes;


    private CommonMacaroonInfos(Long timestamp, Map<String, String> labels, Map<String, String> attributes) {
      this.timestamp = timestamp;
      this.labels = labels;
      this.attributes = attributes;
    }
  }

  private CommonMacaroonInfos extractCommonInfosFromMacaroon(Macaroon macaroon, MacarronsVerifierExtractor mve){
    CaveatDataExtractor<Date> timeExtractor = mve.getExtractorForPrefix(warp_caveat_prefix+"time < ");
    CaveatDataExtractor<Map<String, String>> labelExtractor = mve.getExtractorForPrefix(warp_caveat_prefix+"label = ");
    CaveatDataExtractor<Map<String, String>> attributesExtractor = mve.getExtractorForPrefix(warp_caveat_prefix+"attr = ");

    return new CommonMacaroonInfos(
            (timeExtractor.getData() != null ? timeExtractor.getData().toInstant().toEpochMilli() : null),
            labelExtractor.getData() != null ? labelExtractor.getData() : new HashMap<>(),
            attributesExtractor.getData() != null ? attributesExtractor.getData() : new HashMap<>()
    );
  }

  //@Override
  public ReadToken extractReadToken(String token) throws WarpScriptException {
    if (!token.startsWith(PREFIX)) {
      return null;
    }

    Macaroon macaroon = getMacaroonFromToken(token);

    MacarronsVerifierExtractor verifier = getCommonVerifierForMacaroon(macaroon)
            .satisfyGeneralAndExtract(new AccessCaveatVerifierExtractor(warp_caveat_prefix+"access = ","READ"));


    boolean valid = verifier.isValid(secretKey);

    if(!verifier.isValid(secretKey)){
      return null;
    }

    ReadToken rtoken = new ReadToken();

    CommonMacaroonInfos common = extractCommonInfosFromMacaroon(macaroon,verifier );

    rtoken.setLabels(common.labels);
    rtoken.setAttributes(common.attributes);

    if(common.timestamp != null){
      rtoken.setExpiryTimestamp(common.timestamp);
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
            .satisfyGeneralAndExtract(new AccessCaveatVerifierExtractor(warp_caveat_prefix+"access = ","WRITE"));

    boolean valid = verifier.isValid(secretKey);

    if(!verifier.isValid(secretKey)){
      return null;
    }

    WriteToken wtoken = new WriteToken();

    CommonMacaroonInfos common = extractCommonInfosFromMacaroon(macaroon, verifier);

    wtoken.setLabels(common.labels);
    wtoken.setAttributes(common.attributes);

    if(common.timestamp != null){
      wtoken.setExpiryTimestamp(common.timestamp);
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

  public void readConfig(){
    Properties props = WarpConfig.getProperties();
    if(props.containsKey(MacaroonPluginConfig.MACAROON_SECRET)){
      secretKey = props.getProperty(MacaroonPluginConfig.MACAROON_SECRET);
    }else {
      LOG.error("No secret defined for Macaroon plugin, it will not work and it's dangerous, please add " + MacaroonPluginConfig.MACAROON_SECRET + " entry to your configuration");
    }

    PREFIX = props.getProperty(MacaroonPluginConfig.MACAROON_TOKEN_PREFIX, "macaroon:");

    if(props.containsKey(MacaroonPluginConfig.MACAROON_WARP_CAVEAT_PREFIX)){
      warp_caveat_prefix = props.getProperty(MacaroonPluginConfig.MACAROON_WARP_CAVEAT_PREFIX);
      LOG.info("Macaroon plugin will use " + warp_caveat_prefix + " as a prefix for all caveat");
    }else {
      warp_caveat_prefix = "";
    }

    if(props.containsKey(MacaroonPluginConfig.MACAROON_VALID_CAVEAT_REGEXP)){
      auto_valid_caveat_regexp = Arrays.asList(props.getProperty(MacaroonPluginConfig.MACAROON_VALID_CAVEAT_REGEXP).split(","))
              .stream()
              .map(s -> s.trim())
              .collect(Collectors.toSet());
      auto_valid_caveat_regexp_compiled = auto_valid_caveat_regexp
              .stream()
              .map(s -> Pattern.compile(s))
              .collect(Collectors.toSet());
      LOG.info("Macaroon plugin will automatically validate every caveat with theses regexp: " + auto_valid_caveat_regexp );
    }else {
      auto_valid_caveat_regexp = new HashSet<>();
      auto_valid_caveat_regexp_compiled = new HashSet<>();
    }
  }


  public String getPrefix() {
    return PREFIX;
  }
}
