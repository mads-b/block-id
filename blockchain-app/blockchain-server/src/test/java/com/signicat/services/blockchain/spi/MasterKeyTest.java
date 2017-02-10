package com.signicat.services.blockchain.spi;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Arrays;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.signicat.services.blockchain.crypto.KeyShard;

public class MasterKeyTest {
    private static MasterKey MASTER_KEY;

    static {
        try {
            MasterKey.masterKeySize = 512;
            MASTER_KEY = new MasterKey();
        } catch (final IOException e) {
            fail("Cannot generate master key. " + e.getMessage());
        }
    }

    @Test
    public void isSplittableAndJoinable() throws Exception {
        final KeyShard[] parts = MASTER_KEY.getSplitPrivateKey(4, 6);
        final MasterKey assembledKey = new MasterKey(
                MASTER_KEY.getKeyId(), MASTER_KEY.getPublicKey(), Arrays.copyOfRange(parts, 0, 4));
        assertThat(assembledKey, is(MASTER_KEY));
    }

    @Test(expected = IOException.class)
    public void throwsExceptionIfTooFewPartsAreProvided() throws Exception {
        final KeyShard[] parts = MASTER_KEY.getSplitPrivateKey(4, 6);
        new MasterKey(MASTER_KEY.getKeyId(), MASTER_KEY.getPublicKey(), Arrays.copyOfRange(parts, 0, 3));
    }

    @Test
    public void serializeDeserialize() throws Exception {
        final ObjectMapper om = new ObjectMapper();
        assertThat(om.readValue(om.writeValueAsString(MASTER_KEY), MasterKey.class), is(MASTER_KEY));
    }
}
