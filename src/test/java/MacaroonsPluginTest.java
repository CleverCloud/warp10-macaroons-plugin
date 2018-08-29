/*
 * This Java source file was generated by the Gradle 'init' task.
 */
import com.clevercloud.warp10.plugins.macaroons.MacaroonsPlugin;
import com.clevercloud.warp10.plugins.macaroons.verifiers.AccessCaveatVerifierExtractor;
import com.clevercloud.warp10.plugins.macaroons.verifiers.MapCaveatVerifierExtractor;
import com.github.nitram509.jmacaroons.Macaroon;
import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;
import com.github.nitram509.jmacaroons.verifier.TimestampCaveatVerifier;
import io.warp10.WarpConfig;
import io.warp10.continuum.Configuration;
import io.warp10.quasar.token.thrift.data.ReadToken;
import io.warp10.script.WarpScriptException;

import java.io.IOException;
import java.util.*;

public class MacaroonsPluginTest {

private String secretKey = "test secret key";
private MacaroonsPlugin mp;

     public void testSomeLibraryMethod1() {

         System.out.println("-- First we will play with Macaroons");


         String location = "http://localhost:8080/";
        String identifier = "we used our secret key";
        Macaroon macaroon = new MacaroonsBuilder(location, secretKey, identifier)
                .add_first_party_caveat("time < 2019-01-01T00:00")
                .add_first_party_caveat("label = host=127.0.0.1")
                .add_first_party_caveat("label = name=john")
                .add_first_party_caveat("label = surname=doe")
                .add_first_party_caveat("attr = role=CEO")
                .add_first_party_caveat("access = READ, WRITE")
                .add_first_party_caveat("plop = GLO, GLOU, PRO, ADD")
                .getMacaroon();
        String serialized = macaroon.serialize();

        Macaroon macaroon_1 = MacaroonsBuilder.deserialize(serialized);

        Macaroon macaroon2 = new MacaroonsBuilder(macaroon_1)
                .add_first_party_caveat("access = READ, GLO")
                .add_first_party_caveat("label = surname=grosdada")
                .add_first_party_caveat("attr = role=DBO")
                .add_first_party_caveat("attr = new_attributes=some:data")
                .add_first_party_caveat("plop = GLO, GLOU, ADD")

                .getMacaroon();
        String serialized2 = macaroon2.serialize();

        Macaroon macaroon_d = MacaroonsBuilder.deserialize(serialized2);

        Set<String> plops = new HashSet<>();
        plops.add("GLO");
        plops.add("GLOU");

        MacaroonsVerifier verifier = new MacaroonsVerifier(macaroon_d)
                .satisfyGeneral(new TimestampCaveatVerifier())
                .satisfyGeneral(new MapCaveatVerifierExtractor("label = "))
                .satisfyGeneral(new MapCaveatVerifierExtractor("attr = "))
                .satisfyGeneral(new AccessCaveatVerifierExtractor("READ"))
                .satisfyGeneral(new AccessCaveatVerifierExtractor("plop = ", plops));

        boolean valid = verifier.isValid(secretKey);


        assertTrue("Maccaroons are Valid", valid);




    }

    public void testSomeLibraryMethod2() {

        System.out.println("-- First we will play with Macaroons");


        String location = "http://localhost:8080/";
        String identifier = "we used our secret key";
        Macaroon macaroon = new MacaroonsBuilder(location, secretKey, identifier)
                .add_first_party_caveat("time < 2019-01-01T00:00")
                .add_first_party_caveat("label = host=127.0.0.1")
                .add_first_party_caveat("label = name=john")
                .add_first_party_caveat("label = surname=doe")
                .add_first_party_caveat("attr = role=CEO")
                .add_first_party_caveat("access = READ, WRITE")
                .getMacaroon();
        String serialized = macaroon.serialize();
   //     System.out.println("🎂 Serialized: " + serialized);

        Macaroon macaroon_1 = MacaroonsBuilder.deserialize(serialized);
        String identifier2 = "we used our secret key";

        Macaroon macaroon2 = new MacaroonsBuilder(macaroon_1)
                .add_first_party_caveat("access = READ, GLO")
                .add_first_party_caveat("label = surname=grosdada")
                .add_first_party_caveat("attr = role=DBO")
                .add_first_party_caveat("attr = new_attributes=some:data")

                .getMacaroon();
        String serialized2 = macaroon2.serialize();
 //       System.out.println("🍰 Serialized: " + serialized2);

    //    System.out.println("'macaroon: "+serialized+"' TOKENINFO");
    //    System.out.println("'macaroon: "+serialized2+"' TOKENINFO");


        System.out.println("--");
        System.out.println("-- now play with macaroon -> warp10 tokens");




        try {
            ReadToken rtoken = mp.extractReadToken(mp.getPrefix() + serialized2);

            Map<String, String> tklabel = rtoken.getLabels();
            Map<String, String> needed_labels = new HashMap<>();
            needed_labels.put("surname", "doe");
            needed_labels.put("host", "127.0.0.1");
            needed_labels.put("name", "john");
            Boolean blabel = tklabel.equals(needed_labels);
            assertTrue("Labels are the good ones", blabel);


            Map<String, String> tkattr = rtoken.getAttributes();
            Map<String, String> needed_attr = new HashMap<>();
            needed_attr.put("role", "CEO");
            needed_attr.put("new_attributes", "some:data");
            Boolean battr = tkattr.equals(needed_attr);
            assertTrue("Attributes are the good ones", battr);

            Macaroon mgroovytrue = new MacaroonsBuilder(macaroon2)
                    .add_first_party_caveat("groovy = true")
                    .getMacaroon();
            ReadToken readTokengroovy = mp.extractReadToken(mp.getPrefix() + mgroovytrue.serialize());
            assertTrue("Groovy is valid", readTokengroovy.isGroovy());


            Macaroon mgroovyfalse = new MacaroonsBuilder(mgroovytrue)
                    .add_first_party_caveat("groovy = false")
                    .getMacaroon();
            ReadToken rtgroovyfalse = mp.extractReadToken(mp.getPrefix() + mgroovyfalse.serialize());
            assertTrue("Groovy is false now", !rtgroovyfalse.isGroovy());


            Macaroon mgroovyfalse2 = new MacaroonsBuilder(mgroovyfalse)
                    .add_first_party_caveat("groovy = true")
                    .getMacaroon();
            ReadToken rtgroovyfalse2 = mp.extractReadToken(mp.getPrefix() + mgroovyfalse2.serialize());
            assertTrue("Groovy is still false", !rtgroovyfalse2.isGroovy());

            Macaroon munvalid = new MacaroonsBuilder(macaroon)
                    .add_first_party_caveat("access = WRITE")
                    .getMacaroon();
            ReadToken rtunvalid = mp.extractReadToken(mp.getPrefix() + munvalid.serialize());
            assertTrue("Write token will return null", rtunvalid == null);


            Macaroon mlookuptrue = new MacaroonsBuilder(macaroon2)
                    .add_first_party_caveat("lookup = true")
                    .getMacaroon();
            ReadToken readTokenlookup = mp.extractReadToken(mp.getPrefix() + mlookuptrue.serialize());
            assertTrue("Lookup is valid", readTokenlookup.isLookup());

        } catch (WarpScriptException e) {
            e.printStackTrace();
        }



        // TODO, find a way to run tests in a more clean way


    }

    private void assertTrue(String s, boolean valid) {
        System.out.print("      ");
        System.out.print(valid ? "✅ Success: " : "❌ Error: ");
        System.out.println(s);
    }

    private void init(String file) throws IOException {
        /*try {

            System.setProperty(Configuration.WARP10_QUIET, "true");
            System.setProperty(Configuration.WARPSCRIPT_REXEC_ENABLE, "true");

            if (null == System.getProperty(Configuration.WARP_TIME_UNITS)) {
                System.setProperty(Configuration.WARP_TIME_UNITS, "us");
            }
      //      WarpConfig.setProperties((String) null);
        } catch (IOException e) {
            e.printStackTrace();
        }
*/
         WarpConfig.setProperties(file);

        mp = new MacaroonsPlugin();
        mp.readConfig();
    }

    public static void main(String[] args) throws IOException {
         if (args.length < 1){
             System.out.println("the first argument need to be a warp10.conf file path");
         }


        MacaroonsPluginTest mpt = new MacaroonsPluginTest();
        mpt.init(args[0]);
        mpt.testSomeLibraryMethod1();
        mpt.testSomeLibraryMethod2();
    }


}
