package org.connectbot;

import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;

import java.security.PublicKey;

import de.cotech.hw.util.Hwsecurity25519PublicKey;

class SecurityKey25519Converter {

    /**
     * Hwsecurity25519PublicKey returned by the SDK are just a wrapper around the raw key bytes.
     * So create a new Ed25519PublicKey object based on these key bytes.
     */
    static PublicKey hwsecurityToConnectbot(PublicKey publicKey) {
        if (publicKey instanceof Hwsecurity25519PublicKey) {
            return new Ed25519PublicKey(publicKey.getEncoded());
        } else {
            return publicKey;
        }
    }
}
