/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2019 Dominik Schürmann <dominik@cotech.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connectbot;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;

import org.connectbot.service.SecurityKeyService;

import com.trilead.ssh2.auth.SignatureProxy;
import com.trilead.ssh2.crypto.SimpleDERReader;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;
import com.trilead.ssh2.packets.TypesWriter;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import androidx.annotation.WorkerThread;
import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.ui.SecurityKeyDialogInterface;

public class SecurityKeySignatureProxy extends SignatureProxy {
	private static final String TAG = "CB.SKSignatureProxy";

	private CountDownLatch mResultReadyLatch;

	private SecurityKeyAuthenticator mSecurityKeyAuthenticator;
	private SecurityKeyDialogInterface dialogInterface;

	private SecurityKeyService mSecurityKeyService = null;
	private boolean cancelled;

	public SecurityKeySignatureProxy(PublicKey publicKey, String pubkeyNickname, Context appContext) {
		super(publicKey);

		mResultReadyLatch = new CountDownLatch(1);

		ServiceConnection mSecurityKeyServiceConnection = new ServiceConnection() {
			@Override
			public void onServiceConnected(ComponentName className, IBinder service) {
				mSecurityKeyService = ((SecurityKeyService.SecurityKeyServiceBinder) service).getService();
				mSecurityKeyService.setSignatureProxy(SecurityKeySignatureProxy.this);
				mSecurityKeyService.startActivity(pubkeyNickname);
			}

			@Override
			public void onServiceDisconnected(ComponentName className) {
				mSecurityKeyService = null;
			}
		};
		appContext.bindService(new Intent(appContext, SecurityKeyService.class), mSecurityKeyServiceConnection,
				Context.BIND_AUTO_CREATE);
	}

	public void setAuthenticator(SecurityKeyDialogInterface dialogInterface, SecurityKeyAuthenticator securityKeyAuthenticator) {
		this.mSecurityKeyAuthenticator = securityKeyAuthenticator;
		this.dialogInterface = dialogInterface;
		mResultReadyLatch.countDown();
	}

	public void cancel() {
		cancelled = true;
		mResultReadyLatch.countDown();
	}

	@Override
	public byte[] sign(final byte[] challenge, final String hashAlgorithm) throws IOException {
		while (true) {
			waitForSecurityKey();
			if (cancelled) {
				throw new IOException("Cancelled!");
			}
			byte[] signature = tryAuthOperation(challenge, hashAlgorithm);
			if (signature != null) {
				return signature;
			}
		}
	}

	@WorkerThread
	private byte[] tryAuthOperation(byte[] challenge, String hashAlgorithm) throws IOException {
		try {
			byte[] ds = mSecurityKeyAuthenticator.authenticateWithDigest(challenge, hashAlgorithm);
			byte[] encodedSignature = encodeSignature(ds, hashAlgorithm);

			dialogInterface.dismiss();
			return encodedSignature;
		} catch (IOException e) {
			dialogInterface.postError(e);
			return null;

		} catch (NoSuchAlgorithmException e) {
			throw new IOException("NoSuchAlgorithmException");
		}
	}

	private void waitForSecurityKey() {
		try {
			mResultReadyLatch.await();
			mResultReadyLatch = new CountDownLatch(1);
		} catch (InterruptedException e) {
			throw new RuntimeException("Error waitForSecurityKey(): interrupted");
		}
	}

	/**
	 * Based on methods from AuthenticationManager in sshlib
	 */
	private byte[] encodeSignature(byte[] ds, String hashAlgorithm) throws IOException {
		PublicKey publicKey = getPublicKey();
		if (publicKey instanceof RSAPublicKey) {
			switch (hashAlgorithm) {
			case SHA512: {
				return encodeRSASHA512Signature(ds);
			}
			case SHA256: {
				return encodeRSASHA256Signature(ds);
			}
			case SHA1: {
				return encodeSignature(ds);
			}
			default:
				throw new IOException("Unsupported algorithm in SecurityKeySignatureProxy!");
			}
		} else if (publicKey instanceof ECPublicKey) {
			ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
			return encodeSSHECDSASignature(ds, ecPublicKey.getParams());
		} else if (publicKey instanceof Ed25519PublicKey) {
			return encodeSSHEd25519Signature(ds);
		} else {
			throw new IOException("Unsupported algorithm in SecurityKeySignatureProxy!");
		}
	}

	private static final String ID_SSH_RSA = "ssh-rsa";
	private static final String ID_RSA_SHA_2_256 = "rsa-sha2-256";
	private static final String ID_RSA_SHA_2_512 = "rsa-sha2-512";
	private static final String ECDSA_SHA2_PREFIX = "ecdsa-sha2-";
	private static final String ED25519_ID = "ssh-ed25519";

	/**
	 * Based on method RSASHA1Verify.encodeSignature in sshlib
	 */
	private static byte[] encodeSignature(byte[] s) throws IOException
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString(ID_SSH_RSA);

		/* S is NOT an MPINT. "The value for 'rsa_signature_blob' is encoded as a string
		 * containing s (which is an integer, without lengths or padding, unsigned and in
		 * network byte order)."
		 */

		/* Remove first zero sign byte, if present */

		if ((s.length > 1) && (s[0] == 0x00))
			tw.writeString(s, 1, s.length - 1);
		else
			tw.writeString(s, 0, s.length);

		return tw.getBytes();
	}

	/**
	 * Based on method RSASHA512Verify.encodeRSASHA512Signature in sshlib
	 */
	private static byte[] encodeRSASHA512Signature(byte[] s)
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString(ID_RSA_SHA_2_512);

		/* S is NOT an MPINT. "The value for 'rsa_signature_blob' is encoded as a string
		 * containing s (which is an integer, without lengths or padding, unsigned and in
		 * network byte order)."
		 */

		/* Remove first zero sign byte, if present */

		if ((s.length > 1) && (s[0] == 0x00))
			tw.writeString(s, 1, s.length - 1);
		else
			tw.writeString(s, 0, s.length);

		return tw.getBytes();
	}

	/**
	 * Based on method RSASHA256Verify.encodeRSASHA256Signature in sshlib
	 */
	private static byte[] encodeRSASHA256Signature(byte[] s) throws IOException
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString(ID_RSA_SHA_2_256);

		/* S is NOT an MPINT. "The value for 'rsa_signature_blob' is encoded as a string
		 * containing s (which is an integer, without lengths or padding, unsigned and in
		 * network byte order)."
		 */

		/* Remove first zero sign byte, if present */

		if ((s.length > 1) && (s[0] == 0x00))
			tw.writeString(s, 1, s.length - 1);
		else
			tw.writeString(s, 0, s.length);

		return tw.getBytes();
	}

	/**
	 * Based on method ECDSASHA2Verify.encodeSSHECDSASignature in sshlib 2.2.15
	 */
	private byte[] encodeSSHECDSASignature(byte[] sig, ECParameterSpec params) throws IOException
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString(getSshKeyType(params));

		/*
		 * This is a signature in ASN.1 DER format. It should look like:
		 *  0x30 <len>
		 *      0x02 <len> <data[len]>
		 *      0x02 <len> <data[len]>
		 */

		SimpleDERReader reader = new SimpleDERReader(sig);
		reader.resetInput(reader.readSequenceAsByteArray());

		BigInteger r = reader.readInt();
		BigInteger s = reader.readInt();

		// Write the <r,s> to its own types writer.
		TypesWriter rsWriter = new TypesWriter();
		rsWriter.writeMPInt(r);
		rsWriter.writeMPInt(s);
		byte[] encoded = rsWriter.getBytes();
		tw.writeString(encoded, 0, encoded.length);

		return tw.getBytes();
	}
	private static final Map<Integer, String> CURVE_SIZES = new TreeMap<Integer, String>();
	static {
		CURVE_SIZES.put(256, "nistp256");
		CURVE_SIZES.put(384, "nistp384");
		CURVE_SIZES.put(521, "nistp521");
	}
	private static String getSshKeyType(ECParameterSpec params) throws IOException {
		return ECDSA_SHA2_PREFIX + getCurveName(params);
	}
	private static String getCurveName(ECParameterSpec params) throws IOException {
		int fieldSize = getCurveSize(params);
		final String curveName = getCurveName(fieldSize);
		if (curveName == null) {
			throw new IOException("invalid curve size " + fieldSize);
		}
		return curveName;
	}
	private static String getCurveName(int fieldSize) {
		String curveName = CURVE_SIZES.get(fieldSize);
		if (curveName == null) {
			return null;
		}
		return curveName;
	}
	private static int getCurveSize(ECParameterSpec params) {
		return params.getCurve().getField().getFieldSize();
	}

	/**
	 * Based on method Ed25519Verify.encodeSSHEd25519Signature in sshlib
	 */
	private static byte[] encodeSSHEd25519Signature(byte[] sig) {
		TypesWriter tw = new TypesWriter();

		tw.writeString(ED25519_ID);
		tw.writeString(sig, 0, sig.length);

		return tw.getBytes();
	}
}