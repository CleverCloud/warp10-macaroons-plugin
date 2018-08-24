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

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

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



  //@Override
  public ReadToken extractReadToken(String token) throws WarpScriptException {
    System.out.println("read");
    if (!token.startsWith(PREFIX)) {
      return null;
    }

    ReadToken rtoken = new ReadToken();

    System.out.println(token);
    Macaroon macaroon = MacaroonsBuilder.deserialize(token.substring(PREFIX.length()));


    MacaroonsVerifier verifier = new MacaroonsVerifier(macaroon)
            .satisfyGeneral(new TimestampCaveatVerifier());
    boolean valid = verifier.isValid(secretKey);


    System.out.println("😇😇😇  valid: " + valid + "\n" + macaroon.inspect());

    if(!verifier.isValid(secretKey)){
      return null;
    }


    List<CaveatPacket> caveats = Arrays.asList(macaroon.caveatPackets);

    for (CaveatPacket caveat : caveats) {
      System.out.println("-> " + caveat.getValueAsText());

      if(caveat.getValueAsText().startsWith("time < ")){
        rtoken.setExpiryTimestamp((new DateTime(caveat.getValueAsText().substring("time < ".length()))).getMillis());
      }
    }

    if(!rtoken.isSetExpiryTimestamp()){
      rtoken.setExpiryTimestamp(((new DateTime()).plus(Duration.standardHours(2))).getMillis());
    }
    // .... populate the ReadToken
    
    return rtoken;
  }
  
  //@Override
  public WriteToken extractWriteToken(String token) throws WarpScriptException {
    System.out.println("write");
    System.out.println(token);
    if (!token.startsWith(PREFIX)) {
      return null;
    }
    System.out.println(token);

    WriteToken wtoken = new WriteToken();
    
    // .... populate the WriteToken
    
    return wtoken;
  }
  
  //@Override
  public void init(Properties properties) {
    LOG.info("Registering Macaroon authentication plugin");
    Tokens.register(this);

    String location = "http://localhost:8080/";
    String identifier = "we used our secret key";
    Macaroon macaroon = new MacaroonsBuilder(location, secretKey, identifier)
            .add_first_party_caveat("time < 2015-01-01T00:00")
            .getMacaroon();
    String serialized = macaroon.serialize();
    System.out.println("Serialized: " + serialized);

    Macaroon macaroon2 = new MacaroonsBuilder(location, secretKey, identifier + "1")
            .getMacaroon();
    String serialized2 = macaroon2.serialize();
    System.out.println("Serialized: " + serialized2);

  }
}
