package com.signicat.services.blockchain.spi;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.text.ParseException;
import java.util.Objects;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.google.common.base.MoreObjects;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.signicat.services.blockchain.crypto.KeyShard;
import com.signicat.services.blockchain.crypto.TiemensShamirWrapper;

/**
 * Master key for this identity. Splittable into parts and reassemblable.
 */
public class MasterKey {
    private static final Logger LOG = LogManager.getLogger(MasterKey.class);

    // Actual number of bits in the private key will be this number * 4.
    protected static int masterKeySize = 1024;

    private final String keyId;
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public MasterKey() throws IOException {
        this.keyId = UUID.randomUUID().toString();
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            // Paranoia-strength RSA key.
            keyGen.initialize(new RSAKeyGenParameterSpec(masterKeySize, RSAKeyGenParameterSpec.F4));
            final KeyPair keyPair = keyGen.generateKeyPair();
            this.publicKey = (RSAPublicKey) keyPair.getPublic();
            this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
            LOG.info("New master key with ID " + keyId + " generated.");
        } catch (final NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            LOG.error("Yikes! RSA not supported!", e);
            throw new IOException("RSA is not supported! Cannot generate Master Key!", e);
        }
    }

    public MasterKey(final String keyId, final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        this.keyId = Objects.requireNonNull(keyId);
        this.publicKey = Objects.requireNonNull(publicKey);
        this.privateKey = Objects.requireNonNull(privateKey);
    }

    public MasterKey(final String keyId, final RSAPublicKey publicKey, final KeyShard[] privateKeyParts)
            throws IOException {
        this.keyId = Objects.requireNonNull(keyId);
        this.publicKey = Objects.requireNonNull(publicKey);
        final byte[] privateKeyBytes;
        try {
            /*privateKeyBytes = new Shamir(
                    privateKeyParts[0].getNeededToReassemble(),
                    privateKeyParts[0].getTotalNumberOfShares())
                    .combine(privateKeyParts);*/
            privateKeyBytes = TiemensShamirWrapper.combine(privateKeyParts).toByteArray();
           // privateKeyBytes = Secrets.join(Objects.requireNonNull(privateKeyParts));
        } catch (final IllegalArgumentException e) {
            throw new IOException("Too few key parts provided!", e);
        }

        try {
            final KeyFactory factory = KeyFactory.getInstance("RSA");
            final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
            this.privateKey = (RSAPrivateKey) factory.generatePrivate(spec);
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
            LOG.error("Failed while assembling Master Key", e);
            throw new IOException("failed while assembling Master Key", e);
        }
    }

    public String getKeyId() {
        return keyId;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public KeyShard[] getSplitPrivateKey(final int numberNeededToReassemble, final int numberOfParts) {
        return TiemensShamirWrapper.split(numberNeededToReassemble, numberOfParts, this);
       // return new Shamir(numberNeededToReassemble, numberOfParts).split(new BigInteger(privateKey.getEncoded()));
        //return Secrets.split(privateKey.getEncoded(), numberOfParts, numberNeededToReassemble, new SecureRandom());
    }

    @JsonValue
    public String getValue() {
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(keyId).build().toJSONString();
    }

    @JsonCreator
    public static MasterKey fromString(final String json) throws IOException {
        try {
            final RSAKey key = RSAKey.parse(json);
            return new MasterKey(key.getKeyID(), key.toRSAPublicKey(), key.toRSAPrivateKey());
        } catch (final ParseException | JOSEException e) {
            throw new IOException("Got corrupt master key!", e);
        }
    }

    @Override
    public boolean equals(final Object o) {
        if(!(o instanceof MasterKey)) {
            return false;
        }
        final MasterKey other = (MasterKey) o;
        return Objects.equals(keyId, other.keyId)
                && Objects.equals(publicKey, other.publicKey)
                && Objects.equals(privateKey, other.privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, publicKey, privateKey);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(MasterKey.class)
                .add("keyId", keyId)
                .add("publicKey", publicKey)
                .add("privateKey", "XXXXXx")
                .toString();
    }
}
