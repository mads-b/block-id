package com.signicat.services.blockchain.spi;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Memory-only implementation of a node network..
 */
public class DummyNodeNetwork implements NodeNetwork {
    private final Map<String, MasterKey> keys = new HashMap<>();
    private final Map<String, ClientSignedAssertion> assertion = new HashMap<>();

    @Override
    public void pushMasterKey(final MasterKey masterKey) throws IOException {
        keys.put(masterKey.getKeyId(), new MasterKey(masterKey.getKeyId(), masterKey.getPublicKey(), masterKey.getSplitPrivateKey(10, 15)));
    }

    @Override
    public MasterKey pushAssertion(final Assertion assertion) throws IOException {
        return null;
    }

    @Override
    public void pushAssertion(final ClientSignedAssertion assertion) throws IOException {
    }

    @Override
    public List<String> listBlockIds(final MasterKey masterKey) throws IOException {
        return null;
    }

    @Override
    public Assertion getBlock(final MasterKey masterKey, final String blockId) throws IOException {
        return null;
    }
}
