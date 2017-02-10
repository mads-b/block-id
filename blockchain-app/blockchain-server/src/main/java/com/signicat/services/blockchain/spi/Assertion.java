package com.signicat.services.blockchain.spi;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.signicat.services.blockchain.crypto.HKDF;

/**
 * Data from an IdP, encrypted by TM and signed by the IdP.
 *
 * These JWTs are a bit special. The Claims in the JWT are individually encrypted, using multiple keys.
 * This means that _every_single_claim_ in the JWT is a JWT itself, except two special ones:
 * - A "T-key", used for "stretching" the master key, yielding the claim encryption (base) key.
 * - A sub Claim, clear text.
 *
 * The Master Key and the T key together, using HKDF, yields the MT key,
 * which is unique for this Assertion.
 *
 * Furthermore, the MT key and the claim name together, yields the MT1 key,
 * unique for each claim in this Assertion.
 *
 * Given a MT1 key, a Service Provider may decrypt the corresponding Claim and that Claim only.
 */
public class Assertion {
    private static final EncryptionMethod CLAIM_ENCRYPTION_METHOD = EncryptionMethod.A256CBC_HS512;
    private static final Set<String> PLAINTEXT_CLAIMS = ImmutableSet.of("tkey", "iss", "sub");
    private static final ObjectMapper OM = new ObjectMapper();

    private final SignedJWT jwt;

    public Assertion(final SignedJWT jwt) {
        this.jwt = jwt;
    }

    public Assertion(
            final JWTClaimsSet claimsPlainText,
            final byte[] mtKey,
            final byte[] tkey,
            final PrivateKey idpKey) throws IOException {
        final JWTClaimsSet.Builder encJwtBuilder = new JWTClaimsSet.Builder()
                .claim("tkey", Base64.encode(tkey));

        for (final Map.Entry<String, Object> claim : claimsPlainText.getClaims().entrySet()) {
            if (PLAINTEXT_CLAIMS.contains(claim.getKey())) {
                encJwtBuilder.claim(claim.getKey(), claim.getValue());
                continue;
            }
            final byte[] claimKey = makeClaimKey(mtKey, claim.getKey());
            final JWEObject jweObject = new JWEObject(
                    new JWEHeader(JWEAlgorithm.DIR, CLAIM_ENCRYPTION_METHOD),
                    new Payload(OM.writeValueAsString(claim.getValue())));
            try {
                jweObject.encrypt(new DirectEncrypter(claimKey));
            } catch (final JOSEException e) {
                throw new IOException("Failed when encrypting Claim " + claim.getKey(), e);
            }
            encJwtBuilder.claim(claim.getKey(), jweObject.serialize());
        }
        final SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), encJwtBuilder.build());
        final JWSSigner signer = new RSASSASigner(idpKey);
        try {
            signedJWT.sign(signer);
        } catch (final JOSEException e) {
            throw new IOException("Failed when signing Assertion.", e);
        }
        this.jwt = signedJWT;
    }

    public void validateIdPSignature(final PublicKey idpPubKey) throws IOException {
        try {
            final JWSVerifier verifier = new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), idpPubKey);
            jwt.verify(verifier);
        } catch (final JOSEException e) {
            throw new IOException("Failed verifying IdP signature: ", e);
        }
    }

    public JWTClaimsSet decryptClaims(final byte[] mtKey) throws IOException {
        try {
            final JWTClaimsSet encClaims = jwt.getJWTClaimsSet();

            final JWTClaimsSet.Builder claimBuilder = new JWTClaimsSet.Builder();
            for (final Map.Entry<String, Object> encClaim : encClaims.getClaims().entrySet()) {
                if (PLAINTEXT_CLAIMS.contains(encClaim.getKey())) {
                    claimBuilder.claim(encClaim.getKey(), encClaim.getValue());
                    continue;
                }

                final byte[] claimKey = makeClaimKey(mtKey, encClaim.getKey());
                claimBuilder.claim(encClaim.getKey(), decryptClaim(encClaim.getKey(), claimKey, Object.class));
            }
            return claimBuilder.build();
        } catch (final ParseException e) {
            throw new IOException("Could not parse JWT within.");
        }
    }

    public <T> T decryptClaim(final String claimName, final byte[] claimKey, final Class<T> type) throws IOException {
        final JWEObject jwe;
        try {
            jwe = JWEObject.parse((String)jwt.getJWTClaimsSet().getClaim(claimName));
            jwe.decrypt(new DirectDecrypter(claimKey));
            return OM.readValue(jwe.getPayload().toString(), type);
        } catch (ParseException | JOSEException e) {
            throw new IOException("Something went wrong decrypting the assertion Claims..", e);
        }
    }

    private byte[] makeClaimKey(final byte[] mtKey, final String claimName) {
        return HKDF.hkdfExpand(
                HKDF.hkdfExtract(claimName.getBytes(), mtKey), new byte[] {}, CLAIM_ENCRYPTION_METHOD.cekBitLength() / 8);
    }

    public SignedJWT getJwt() {
        return jwt;
    }

    @JsonCreator
    public static Assertion valueOf(final String jwt) throws ParseException {
        return new Assertion(SignedJWT.parse(jwt));
    }

    @JsonValue
    public String getValue() {
        return jwt.serialize();
    }

    @Override
    public boolean equals(final Object o) {
        if(!(o instanceof Assertion)) {
            return false;
        }
        return Objects.equals(jwt.serialize(), ((Assertion) o).jwt.serialize());
    }
}
