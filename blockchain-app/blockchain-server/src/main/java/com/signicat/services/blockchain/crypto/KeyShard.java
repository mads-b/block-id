package com.signicat.services.blockchain.crypto;

import java.math.BigInteger;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;

/**
 * Bean representation of one shard share of a master key.
 */
public class KeyShard {
    private final String keyId;
    private final int shareIndex;
    private final int neededToReassemble;
    private final BigInteger prime;
    private final BigInteger share;
    private final BigInteger pubkey;

    @JsonCreator
    public KeyShard(
            @JsonProperty("keyId") final String keyId,
            @JsonProperty("shareIndex") final int shareIndex,
            @JsonProperty("minSharesForReassembly") final int neededToReassemble,
            @JsonProperty("prime") final BigInteger prime,
            @JsonProperty("share") final BigInteger share,
            @JsonProperty("pubkey") final BigInteger pubkey) {
        this.keyId = keyId;
        this.shareIndex = shareIndex;
        this.neededToReassemble = neededToReassemble;
        this.prime = prime;
        this.share = share;
        this.pubkey = pubkey;
    }

    @JsonProperty("keyId")
    public String getKeyId() {
        return keyId;
    }

    @JsonProperty("shareIndex")
    public int getShareIndex() {
        return shareIndex;
    }

    @JsonProperty("minSharesForReassembly")
    public int getNeededToReassemble() {
        return neededToReassemble;
    }

    @JsonProperty("prime")
    public BigInteger getPrime() {
        return prime;
    }

    @JsonProperty("share")
    public BigInteger getShare() {
        return share;
    }

    @JsonProperty("pubkey")
    public BigInteger getPubkey() {
        return pubkey;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(KeyShard.class)
                .add("keyId", keyId)
                .add("shareIndex", shareIndex)
                .add("neededToReassemble", neededToReassemble)
                .add("prime", prime)
                .add("share", share)
                .add("pubKey", pubkey)
                .toString();
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(keyId, shareIndex, neededToReassemble, prime, share, pubkey);
    }

    @Override
    public boolean equals(final Object o) {
        if(!(o instanceof KeyShard)) {
            return false;
        }
        final KeyShard other = (KeyShard) o;
        return Objects.equal(keyId, other.keyId)
                && Objects.equal(shareIndex, other.shareIndex)
                && Objects.equal(neededToReassemble, other.neededToReassemble)
                && Objects.equal(prime, other.prime)
                && Objects.equal(share, other.share)
                && Objects.equal(pubkey, other.pubkey);
    }
}