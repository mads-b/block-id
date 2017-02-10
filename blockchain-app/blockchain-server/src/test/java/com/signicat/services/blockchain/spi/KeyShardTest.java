package com.signicat.services.blockchain.spi;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.math.BigInteger;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.signicat.services.blockchain.crypto.KeyShard;

public class KeyShardTest {
    @Test
    public void serializeDeserialize() throws Exception {
        final KeyShard shard = new KeyShard("keyId", 1, 4, BigInteger.TEN, BigInteger.TEN, BigInteger.TEN);
        final ObjectMapper om = new ObjectMapper();
        assertThat(om.readValue(om.writeValueAsString(shard), KeyShard.class), is(shard));
    }
}
