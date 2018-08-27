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

import com.clevercloud.warp10.plugins.macaroons.verifiers.AccessCaveatVerifier;
import com.clevercloud.warp10.plugins.macaroons.verifiers.PrefixValidationCaveatVerifier;
import com.github.nitram509.jmacaroons.CaveatPacket;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;
import com.github.nitram509.jmacaroons.verifier.TimestampCaveatVerifier;
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
  private static final String PREFIX = "macaroon:";

  private static final Logger LOG = LoggerFactory.getLogger(MacaroonsPlugin.class);

  // TODO get it from conf file
  private String secretKey = "this is our super secret key; only we should know it";


  private MacaroonsVerifier getCommonVerifierForMacaroon(Macaroon macaroon ){
    return new MacaroonsVerifier(macaroon)
            .satisfyGeneral(new TimestampCaveatVerifier())
            .satisfyGeneral(new PrefixValidationCaveatVerifier("label = "))
            .satisfyGeneral(new PrefixValidationCaveatVerifier("attr = "));
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

  private CommonMacaroonInfos extractCommonInfosFromMacaroon(Macaroon macaroon){
    List<CaveatPacket> caveats = Arrays.asList(macaroon.caveatPackets);

    Map<String,String> labels = new HashMap<>();
    Map<String,String> attributes = new HashMap<>();
    Long timestamp = null;

    for (CaveatPacket caveat : caveats) {
      System.out.println("-> " + caveat.getValueAsText());

      if(caveat.getValueAsText().startsWith("time < ")){
        timestamp = (new DateTime(caveat.getValueAsText().substring("time < ".length()).trim())).getMillis();
      }
      if(caveat.getValueAsText().startsWith("label = ")){
        String line = caveat.getValueAsText().substring("label = ".length());
        int whereIsEqual = line.indexOf("=");
        String k = line.substring(0,whereIsEqual).trim();
        String v = line.substring(whereIsEqual+1).trim();
        labels.putIfAbsent(k,v);
      }
      if(caveat.getValueAsText().startsWith("attr = ")){
        String line = caveat.getValueAsText().substring("attr = ".length());
        int whereIsEqual = line.indexOf("=");
        String k = line.substring(0,whereIsEqual).trim();
        String v = line.substring(whereIsEqual+1).trim();
        attributes.putIfAbsent(k,v);
      }

    }

    return new CommonMacaroonInfos(timestamp, labels, attributes);
  }

  //@Override
  public ReadToken extractReadToken(String token) throws WarpScriptException {
    System.out.println("read");
    if (!token.startsWith(PREFIX)) {
      return null;
    }

    Macaroon macaroon = getMacaroonFromToken(token);

    MacaroonsVerifier verifier = getCommonVerifierForMacaroon(macaroon)
            .satisfyGeneral(new AccessCaveatVerifier("READ"));

    boolean valid = verifier.isValid(secretKey);


    System.out.println("😇😇😇  valid: " + valid + "\n" + macaroon.inspect());
    System.out.println("😇😇😇");

    if(!verifier.isValid(secretKey)){
      return null;
    }


    ReadToken rtoken = new ReadToken();

    CommonMacaroonInfos common = extractCommonInfosFromMacaroon(macaroon);

    rtoken.setLabels(common.labels);
    rtoken.setAttributes(common.attributes);

// TODO check if we really need to expirate it
    if(common.timestamp != null){
      rtoken.setExpiryTimestamp(common.timestamp);
    }else{
      rtoken.setExpiryTimestamp(((new DateTime()).plus(Duration.standardHours(2))).getMillis());
    }
    // .... populate the ReadToken

    System.out.println(rtoken.getLabels() + " \n" + rtoken.getAttributes());
    System.out.println(rtoken.toString());

    return rtoken;
  }
  
  //@Override
  public WriteToken extractWriteToken(String token) throws WarpScriptException {
    System.out.println("write");
    if (!token.startsWith(PREFIX)) {
      return null;
    }
    Macaroon macaroon = getMacaroonFromToken(token);

    MacaroonsVerifier verifier = getCommonVerifierForMacaroon(macaroon)
            .satisfyGeneral(new AccessCaveatVerifier("WRITE"));

    boolean valid = verifier.isValid(secretKey);


    System.out.println("WRITE 😇😇😇  valid: " + valid + "\n" + macaroon.inspect());
    System.out.println("WRITE 😇😇😇");
    if(!verifier.isValid(secretKey)){
      return null;
    }


    WriteToken wtoken = new WriteToken();

    CommonMacaroonInfos common = extractCommonInfosFromMacaroon(macaroon);

    wtoken.setLabels(common.labels);
    wtoken.setAttributes(common.attributes);

// TODO check if we really need to expirate it
    if(common.timestamp != null){
      wtoken.setExpiryTimestamp(common.timestamp);
    }else{
      wtoken.setExpiryTimestamp(((new DateTime()).plus(Duration.standardHours(2))).getMillis());
    }

    // .... populate the WriteToken
    
    return wtoken;
  }
  
  //@Override
  public void init(Properties properties) {
    LOG.info("Registering Macaroon authentication plugin");
    Tokens.register(this);
  }


  public String getPrefix() {
    return PREFIX;
  }
}
