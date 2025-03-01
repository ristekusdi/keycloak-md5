package io.github.ristekusdi;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

public class MD5HashProvider implements PasswordHashProvider {

	private final String providerId;

	public MD5HashProvider(String providerId) {
		this.providerId = providerId;
	}

	@Override
	public void close() {
	}

	@Override
	public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
		return this.providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
	}

	@Override
	public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
		try {
			MessageDigest md = MessageDigest.getInstance(this.providerId);
			md.update(rawPassword.getBytes());

			// convert the digest byte[] to BigInteger
			var aux = new BigInteger(1, md.digest());

			// convert BigInteger to 32-char lowercase string using leading 0s
			String encodedPassword = String.format("%032x", aux);
			return PasswordCredentialModel.createFromValues(this.providerId, new byte[0], iterations, encodedPassword);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Error encoding password: " + e.getMessage(), e);
		}
	}

	@Override
	public boolean verify(String rawPassword, PasswordCredentialModel credential) {
		String encodedPassword = encodedCredential(rawPassword, credential.getPasswordCredentialData().getHashIterations())
			.getPasswordSecretData().getValue();
		String hash = credential.getPasswordSecretData().getValue();
		return encodedPassword.equals(hash);
	}

}
