package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.security.EncryptionAlgorithms
import io.jsonwebtoken.security.AuthenticatedEncryptionResult
import io.jsonwebtoken.security.DecryptionRequests
import io.jsonwebtoken.security.EncryptionRequest
import io.jsonwebtoken.security.EncryptionRequests
import org.junit.Test

import static org.junit.Assert.assertArrayEquals
import static org.junit.Assert.assertTrue

/**
 * Test case defined in https://tools.ietf.org/html/rfc7518#appendix-B.1
 */
class Aes128CbcHmacSha256Test {

    final byte[] K =
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f] as byte[]

    final byte[] MAC_KEY =
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f] as byte[]

    final byte[] ENC_KEY =
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f] as byte[]

    final byte[] P =
            [0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
             0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
             0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
             0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69, 0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
             0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
             0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
             0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
             0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65] as byte[]

    final byte[] IV =
            [0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04] as byte[]

    final byte[] A =
            [0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
             0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
             0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x73] as byte[]

    final byte[] AL = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x50] as byte[]

    final byte[] E =
            [0xc8, 0x0e, 0xdf, 0xa3, 0x2d, 0xdf, 0x39, 0xd5, 0xef, 0x00, 0xc0, 0xb4, 0x68, 0x83, 0x42, 0x79,
             0xa2, 0xe4, 0x6a, 0x1b, 0x80, 0x49, 0xf7, 0x92, 0xf7, 0x6b, 0xfe, 0x54, 0xb9, 0x03, 0xa9, 0xc9,
             0xa9, 0x4a, 0xc9, 0xb4, 0x7a, 0xd2, 0x65, 0x5c, 0x5f, 0x10, 0xf9, 0xae, 0xf7, 0x14, 0x27, 0xe2,
             0xfc, 0x6f, 0x9b, 0x3f, 0x39, 0x9a, 0x22, 0x14, 0x89, 0xf1, 0x63, 0x62, 0xc7, 0x03, 0x23, 0x36,
             0x09, 0xd4, 0x5a, 0xc6, 0x98, 0x64, 0xe3, 0x32, 0x1c, 0xf8, 0x29, 0x35, 0xac, 0x40, 0x96, 0xc8,
             0x6e, 0x13, 0x33, 0x14, 0xc5, 0x40, 0x19, 0xe8, 0xca, 0x79, 0x80, 0xdf, 0xa4, 0xb9, 0xcf, 0x1b,
             0x38, 0x4c, 0x48, 0x6f, 0x3a, 0x54, 0xc5, 0x10, 0x78, 0x15, 0x8e, 0xe5, 0xd7, 0x9d, 0xe5, 0x9f,
             0xbd, 0x34, 0xd8, 0x48, 0xb3, 0xd6, 0x95, 0x50, 0xa6, 0x76, 0x46, 0x34, 0x44, 0x27, 0xad, 0xe5,
             0x4b, 0x88, 0x51, 0xff, 0xb5, 0x98, 0xf7, 0xf8, 0x00, 0x74, 0xb9, 0x47, 0x3c, 0x82, 0xe2, 0xdb] as byte[]

    final byte[] M =
            [0x65, 0x2c, 0x3f, 0xa3, 0x6b, 0x0a, 0x7c, 0x5b, 0x32, 0x19, 0xfa, 0xb3, 0xa3, 0x0b, 0xc1, 0xc4,
             0xe6, 0xe5, 0x45, 0x82, 0x47, 0x65, 0x15, 0xf0, 0xad, 0x9f, 0x75, 0xa2, 0xb7, 0x1c, 0x73, 0xef] as byte[]

    final byte[] T =
            [0x65, 0x2c, 0x3f, 0xa3, 0x6b, 0x0a, 0x7c, 0x5b, 0x32, 0x19, 0xfa, 0xb3, 0xa3, 0x0b, 0xc1, 0xc4] as byte[]

    @Test
    public void test() {

        def alg = EncryptionAlgorithms.A128CBC_HS256

        EncryptionRequest request = EncryptionRequests.builder()
                .setAdditionalAuthenticatedData(A)
                .setInitializationVector(IV)
                .setKey(K)
                .setPlaintext(P)
                .build();

        def r = alg.encrypt(request);

        assertTrue r instanceof AuthenticatedEncryptionResult
        AuthenticatedEncryptionResult result = r as AuthenticatedEncryptionResult;

        byte[] resultCiphertext = result.getCiphertext()
        byte[] resultTag = result.getAuthenticationTag();
        byte[] resultIv = result.getInitializationVector();

        assertArrayEquals E, resultCiphertext
        assertArrayEquals T, resultTag
        assertArrayEquals IV, resultIv //shouldn't have been altered

        // now test decryption:

        def dreq = DecryptionRequests.builder()
                .setAdditionalAuthenticatedData(A)
                .setCiphertext(resultCiphertext)
                .setInitializationVector(resultIv)
                .setKey(K)
                .setAuthenticationTag(resultTag)
                .build();

        byte[] decryptionResult = alg.decrypt(dreq)

        assertArrayEquals(P, decryptionResult);
    }

}
