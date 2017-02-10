package com.signicat.services.blockchain.crypto;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableList;
import com.signicat.services.blockchain.spi.MasterKey;

/**
 * The Tim Tiemens implementation of Shamir's secret sharing is by far the fastest implementation
 * oavailable, due to it having precomputed (non-secret) primes in the computation. Unfortunately,
 * there's only a CLI interface available, so we wrap that here for hygiene.
 */
public class TiemensShamirWrapper {
    // Not secret. Just a big prime to make cracker's lives miserable.
    private static final String BIG_PRIME = "157607640996539396980767168619254665162064140205521649" +
            "89475434124203282933655939589862107003715166677101125407571543044777723481325492956363" +
            "61148100704669829914105099003597979583648700782189161016331928093984753042903056551071" +
            "50933010308240477164150850996423351212766685316999643752074729072591720569908106360489" +
            "68519743524794085991996233963985456868150905081409788953687311219044518401498470023730" +
            "61365299640504869808871049582851294285515986059971724613645110477176686353214306084464" +
            "53336009081147814413084582939338147587861959112970326498452161846396798549251043793915" +
            "56036655465194711265824060743231408239209341248479205774052055188510126529555657395919" +
            "59443819720984141375256241575434436969771298033559904709248255912750570392474955087961" +
            "75241207577740555065710030994880756784739054875925815647633215216657698475585590372534" +
            "72398544787674849665531782259080829983050492330855708807190073622402032649707981154365" +
            "70026515026196581245460845297156575326557640480014376330451141498650198569959726706737" +
            "41231872112100179929840758413512847095743255928566659734677600731873727650532965712467" +
            "46940862955888268419108770372894733286814419752851775893209562637739448342085575171936" +
            "62779163347885400429286873639238360188728469068385151968602200283380850196449644863498" +
            "21662685119666265899024622199217777834042310029696252930830595748524889851296738775916" +
            "86268120952859813544750555241534230643729995848639838282448338033057507717374281294629" +
            "69505251032664312124230334406378535133857674543456883898021761112664066416978153942247" +
            "72626530479214624881950963781498031610666437418708119814896035439318813120364487411134" +
            "75215045955033195884758467431662911346052028582195186933515645263172818819650285595633" +
            "45760569763353470715021730910974829705499848622724457605544532425406874575667675230241" +
            "1689523405845520904946167157760395791781215664266986897573";

    private TiemensShamirWrapper() {}

    public static KeyShard[] split(
            final int shardsNeededToReconstruct,
            final int totalNumberOfShards,
            final MasterKey masterKey) {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        final PrintStream outputStream = new PrintStream(bos);
        final BigInteger integerKey = new BigInteger(masterKey.getPrivateKey().getEncoded());
        com.tiemens.secretshare.main.cli.MainSplit.main(new String[] {
                "-k", String.valueOf(shardsNeededToReconstruct),
                "-n", String.valueOf(totalNumberOfShards),
                "-m", BIG_PRIME,
                "-sN", integerKey.toString(),
                "-printOne"
        }, null, outputStream);

        final String tiemensOutput = bos.toString();
        final String[] tiemensSplit = tiemensOutput.split("\n");
        final Pattern shareLinePattern = Pattern.compile("Share \\(x:(\\d*)\\) = (\\d.*)");
        final Pattern modulusPattern = Pattern.compile("modulus = (\\d.*)");
        final List<KeyShard> shareLines = new ArrayList<>();
        BigInteger modulus = null;
        for (final String line : tiemensSplit) {
            if (modulus == null) {
                final Matcher modulusMatcher = modulusPattern.matcher(line);
                if (modulusMatcher.matches()) {
                    modulus = new BigInteger(modulusMatcher.group(1));
                }
            }

            final Matcher m = shareLinePattern.matcher(line);
            if (m.matches()) {
                final BigInteger share = new BigInteger(m.group(2).trim());
                shareLines.add(new KeyShard(
                        masterKey.getKeyId(),
                        Integer.valueOf(m.group(1)),
                        shardsNeededToReconstruct,
                        modulus,
                        share,
                        new BigInteger(masterKey.getPublicKey().getEncoded())));
            }
        }

        return shareLines.toArray(new KeyShard[shareLines.size()]);
    }

    public static BigInteger combine(final KeyShard[] shards) {
        final long uniqueShards = Arrays.stream(shards).map(KeyShard::getShareIndex).distinct().count();
        final KeyShard first = shards[0];
        if (uniqueShards < first.getNeededToReassemble()) {
            throw new IllegalArgumentException("Too few shards are provided for reassembly!");
        }

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        final PrintStream outputStream = new PrintStream(bos);
        final ImmutableList.Builder<String> argBuilder = ImmutableList.builder();
        argBuilder.add("-k").add(String.valueOf(uniqueShards));
        argBuilder.add("-primeN").add(shards[0].getPrime().toString());
        for (final KeyShard shard : shards) {
            argBuilder.add("-s" + shard.getShareIndex()).add(shard.getShare().toString());
        }
        final List<String> args = argBuilder.build();
        com.tiemens.secretshare.main.cli.MainCombine.main(args.toArray(new String[args.size()]), null, outputStream);
        final String tiemensOutput = bos.toString();
        final String[] tiemensSplit = tiemensOutput.split("\n");
        final Pattern shareLinePattern = Pattern.compile("secret\\.number = '(\\d.*)'");
        for (final String line : tiemensSplit) {
            final Matcher m = shareLinePattern.matcher(line);
            if (m.matches()) {
                return new BigInteger(m.group(1));
            }
        }
        throw new IllegalStateException("Tiemens library did not output key!");
    }
}
