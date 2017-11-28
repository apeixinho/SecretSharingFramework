package com.secretsharing.tests;

import com.secretsharing.SecretSharingManager;
import com.secretsharing.SecretSharingManagerImpl;
import com.secretsharing.exceptions.FrameworkException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.codec.binary.Base64;
import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;
//import static org.hamcrest.CoreMatchers.*;
//import org.hamcrest.Matchers.*;

/**
 *
 * @author apeixinho
 */
public class SecretSharingManagerTest {

    @Rule
    public ExpectedException exceptions = ExpectedException.none();

    private SecretSharingManager ssm;
    private List<String> secretShares;

    @Before
    public void setUp() throws FrameworkException {
        ssm = new SecretSharingManagerImpl();
    }

    @Test(expected = FrameworkException.class)
    public void secretSharingWithNullParameterK() {

        Integer k = null;
        Integer n = 7;
        String secret = "1 small secret";

        secretShares = ssm.splitSecret(k, n, secret);

    }

    @Test(expected = FrameworkException.class)
    public void secretSharingWithNullParameterN() {

        Integer k = null;
        Integer n = 7;
        String secret = "1 small secret";

        secretShares = ssm.splitSecret(k, n, secret);

    }

    @Test(expected = FrameworkException.class)
    public void secretSharingWithNullParameterSecret() {

        Integer k = null;
        Integer n = 7;
        String secret = "1 small secret";

        secretShares = ssm.splitSecret(k, n, secret);

    }

    @Test(expected = FrameworkException.class)
    public void secretSharingParameter_K_biggerThan_N() {

        Integer k = 7;
        Integer n = 3;
        String secret = "1 small secret";

        secretShares = ssm.splitSecret(k, n, secret);

    }

    @Test(expected = FrameworkException.class)
    public void secretSharingParameter_N_GreaterThan_ModularArithmetic() {

        Integer k = 7;
        Integer n = 11;
        BigInteger smallModArith = BigInteger.valueOf(9);
        String secret = "1 small secret";

        secretShares = ssm.splitSecret(k, n, secret, smallModArith);

    }

    @Test(expected = FrameworkException.class)
    public void secretSharingParameter_Secret_GreaterThan_ModularArithmetic() {

        Integer k = 7;
        Integer n = 11;
        BigInteger smallModArith = BigInteger.valueOf(13);
        String secret = "As armas e os barões assinalados,\n"
                + "Que da ocidental praia Lusitana,\n"
                + "Por mares nunca de antes navegados,\n"
                + "Passaram ainda além da Taprobana,\n"
                + "Em perigos e guerras esforçados,\n"
                + "Mais do que prometia a força humana,\n"
                + "E entre gente remota edificaram\n"
                + "Novo Reino, que tanto sublimaram;";

        secretShares = ssm.splitSecret(k, n, secret, smallModArith);
    }

    @Test(expected = FrameworkException.class)
    public void secretSharing_SplitRecover_NotEnoughShares() {

        Integer k = 4;
        Integer n = 7;
        String secret = "For your eyes only";
        // distribute secret
        secretShares = ssm.splitSecret(k, n, secret);
        // select a subset of secret shares smaller than the threshold
        List<String> notEnoughShares = Arrays.asList(secretShares.get(0), secretShares.get(2));
        // recover the secret
        String invalidRecoveredSecret = ssm.recoverSecret(notEnoughShares, k, n);
        assertFalse(secretShares.isEmpty());
        assertFalse(notEnoughShares.isEmpty());
        assertNull(invalidRecoveredSecret);
        exceptions.expectMessage("Secret Sharing recoverSecret insufficient shares to recover secret");

    }

    @Test()
    public void secretSharing_SplitRecover_TamperedShares() {

        Integer k = 4;
        Integer n = 7;
        String secret = "All your base are belong to us";
        // distribute secret
        secretShares = ssm.splitSecret(k, n, secret);
        // setup fake invalid share
        String invalidShare = "1:87634857687347";
        // tamper/invalidate share at index 1
        secretShares.set(0, Base64.encodeBase64String(invalidShare.getBytes()));

        // assert shares arent empty. Hence shares are distributed
        assertFalse(secretShares.isEmpty());
        // assert that expected list size is 7
        assertEquals(7, secretShares.size());

        String invalidRecoveredSecret = ssm.recoverSecret(secretShares, k, n);
        assertNotEquals(invalidRecoveredSecret, secret);

    }

    @Test()
    public void secretSharing_SplitRecover_with_Specified_ModularArithmetic() {

        Integer k = 4;
        Integer n = 7;
        String secret = "All Our Patents Are Belong To You";
        // specify modular arithmetic
        // constructs a randomly generated positive BigInteger that is probably prime, with the specified bitLength.
        BigInteger modArith = new BigInteger(384, 1, new SecureRandom());
        // distribute secret
        secretShares = ssm.splitSecret(k, n, secret, modArith);
        // assert shares arent empty. Hence shares are distributed
        assertFalse(secretShares.isEmpty());
        // assert that expected list size is 7
        assertEquals(7, secretShares.size());
        // assert that secret is recovered correctly
        String recoveredSecret = ssm.recoverSecret(secretShares, k, n, modArith);
        assertEquals(recoveredSecret, secret);

    }

    @Test()
    public void secretSharing_SplitRecover_without_Specified_ModularArithmetic() {

        Integer k = 4;
        Integer n = 7;
        String secret = "Its just a flesh wound";
        // distribute secret
        secretShares = ssm.splitSecret(k, n, secret);
        // assert shares arent empty. Hence shares are distributed
        assertFalse(secretShares.isEmpty());
        // assert that expected list size is 7
        assertEquals(7, secretShares.size());
        // assert that secret is recovered correctly
        String recoveredSecret = ssm.recoverSecret(secretShares, k, n);
        assertEquals(recoveredSecret, secret);

    }

    @Test()
    public void secretSharing_SplitRecover_without_Specified_ModularArithmeticAndGeneratedSecret() {

        Integer k = 4;
        Integer n = 7;
        // generate random secret
        String secret = new BigInteger(128, 1, new SecureRandom()).toString();
        // distribute secret
        secretShares = ssm.splitSecret(k, n, secret);
        // assert shares arent empty. Hence shares are distributed
        assertFalse(secretShares.isEmpty());
        // assert that expected list size is 7
        assertEquals(7, secretShares.size());
        // assert that secret is recovered correctly
        String recoveredSecret = ssm.recoverSecret(secretShares, k, n);
        assertEquals(recoveredSecret, secret);

    }

}
