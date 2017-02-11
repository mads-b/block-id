package com.signicat.services.blockchain.spi;

import java.io.IOException;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Data from an IdP, encrypted by TM and signed by the IdP. Lastly, signed by this Client.
 */
public class ClientSignedAssertion {
    private final SignedJWT jwt;

    private ClientSignedAssertion(final SignedJWT jwt) {
        this.jwt = jwt;
    }

    @JsonCreator
    public static ClientSignedAssertion valueOf(final String jwt) throws ParseException {
        return new ClientSignedAssertion(SignedJWT.parse(jwt));
    }

    @JsonValue
    public String getValue() {
        return jwt.serialize();
    }

    /**
     * Create a ClientSignedAssertion from an assertion, signed by the provided Master key.
     * the Assertion (with its signature) is base64-encoded and put into the JWT payload.
     *
     * @param masterKey master key to sign the given assertion with
     * @param assertion assertion to sign
     */
    public static ClientSignedAssertion createFromAssertion(
            final MasterKey masterKey, final Assertion assertion) throws IOException {
        try {
            final JWSSigner signer = new RSASSASigner(masterKey.getPrivateKey());
            final SignedJWT assertionJwt = assertion.getJwt();
            final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim("header", assertionJwt.getHeader().toJSONObject())
                    .claim("payload", assertionJwt.getJWTClaimsSet().toJSONObject())
                    .claim("signature", assertionJwt.getSignature())
                    .build();

            final SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(masterKey.getKeyId()).build(),
                    claims);
            // Apply the HMAC
            signedJWT.sign(signer);
            return new ClientSignedAssertion(signedJWT);
        } catch (final JOSEException | ParseException e) {
            throw new IOException("Failed while signing Assertion.", e);
        }
    }

    public Assertion getAssertion(final PublicKey pubKey) throws IOException {
        try {
            final JWSVerifier verifier = new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), pubKey);
            jwt.verify(verifier);
            final JWTClaimsSet claims = jwt.getJWTClaimsSet();
            final Base64URL header = Base64URL.encode(
                    claims.getJSONObjectClaim("header").toJSONString());
            final Base64URL payload = Base64URL.encode(claims.getJSONObjectClaim("payload").toJSONString());
            final Base64URL signature = (Base64URL) claims.getClaim("signature");
            final SignedJWT newJwt = new SignedJWT(header, payload, signature);
            return new Assertion(newJwt);
        } catch (final JOSEException | ParseException e) {
            throw new IOException("Signature validation failed. ", e);
        }
    }

    public SignedJWT getJWT() {
        return jwt;
    }

    @Override
    public boolean equals(final Object o) {
        if (!(o instanceof ClientSignedAssertion)) {
            return false;
        }
        final ClientSignedAssertion other = (ClientSignedAssertion) o;
        return Objects.equals(jwt.serialize(), other.jwt.serialize());
    }
}
