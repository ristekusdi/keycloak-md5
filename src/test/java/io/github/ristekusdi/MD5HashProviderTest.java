package io.github.ristekusdi;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;

public class MD5HashProviderTest {

	@Test
	public void encodeHelloWorld() {
		final var provider = new MD5HashProvider(MD5HashProviderFactory.ID);
		PasswordCredentialModel credential = provider.encodedCredential("hello world", 0);
		assertTrue(provider.verify("hello world", credential));
	}

	@Test
	public void encodeEmptyString() {
		final var provider = new MD5HashProvider(MD5HashProviderFactory.ID);
		PasswordCredentialModel credential = provider.encodedCredential("", 0);
		assertTrue(provider.verify("", credential));
	}

	@Test
	public void ensureIterationParameterIsIgnored() {
		final var provider = new MD5HashProvider(MD5HashProviderFactory.ID);
		PasswordCredentialModel credential = provider.encodedCredential("", 0);
		assertTrue(provider.verify("", credential));

		credential = provider.encodedCredential("", 42); // any random number
		assertTrue(provider.verify("", credential));
	}

	@Test
	public void testHashesWithLeadingZeros() {
		final var provider = new MD5HashProvider(MD5HashProviderFactory.ID);
		PasswordCredentialModel credential = provider.encodedCredential("jk8ssl", 0);
		assertTrue(provider.verify("jk8ssl", credential));
	}
}
