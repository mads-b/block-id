package com.signicat.services.blockchain.spi;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class ClientSignedAssertionTest {
    private MasterKey masterKey;
    private Assertion assertion;
    private SecretKey assertionSecretKey;

    @Before
    public void setUpAssertion() throws Exception {
        masterKey = new MasterKey();
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        assertionSecretKey = keyGen.generateKey();
        final JWSSigner signer = new MACSigner(assertionSecretKey.getEncoded());
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .issueTime(new Date())
                .issuer("https://c2id.com")
                .build();
        final SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        assertion = new Assertion(signedJWT);
    }

    @Test
    public void canSignAssertion() throws Exception {
        assertThat(ClientSignedAssertion.createFromAssertion(masterKey, assertion), is(notNullValue()));
    }

    @Test
    public void canValidateOwnSignature() throws Exception {
        ClientSignedAssertion.createFromAssertion(masterKey, assertion).getAssertion(masterKey.getPublicKey());
    }

    @Test
    public void originalAssertionIsIntact() throws Exception {
        final Assertion originalAssertion = ClientSignedAssertion
                .createFromAssertion(masterKey, assertion)
                .getAssertion(masterKey.getPublicKey());
        final JWSVerifier verifier = new DefaultJWSVerifierFactory()
                .createJWSVerifier(originalAssertion.getJwt().getHeader(), assertionSecretKey);
        originalAssertion.getJwt().verify(verifier);
    }

    @Test
    public void serializeDeserialize() throws Exception {
        final ClientSignedAssertion ass = ClientSignedAssertion.createFromAssertion(masterKey, assertion);
        final ObjectMapper om = new ObjectMapper();
        assertThat(om.readValue(om.writeValueAsString(ass), ClientSignedAssertion.class), is(ass));
    }
}
