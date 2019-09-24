package com.secretsharing;

import com.secretsharing.exceptions.FrameworkException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author apeixinho
 */
public class SecretSharingManagerImpl implements SecretSharingManager {

    // 2048 bit prime to use as the default modular arithmetic
    // this prime has to be greater than the secret
    private static final BigInteger DEFAULT_MOD_ARITH
            = new BigInteger("245720559113293755351195329167945826602678374596592470256185658746207"
                    + "6450558553320739630756792622700016489100210696283442112993369852358438794210"
                    + "4725595477908987684399239360823987907288814644076636729115759502201423105020"
                    + "7932506181846246412022036691429171433289611620607872875219107116333146211638"
                    + "1934071777672745096436913527406807723738263220232673820727823976623324591034"
                    + "9394598137789713667545493714631405838160707543767218593545924046939011685628"
                    + "7989171050623026300422792791016749179137024864798594872366781326823199925203"
                    + "67579969470926954118385802662261031656730172306207265443030407659763136845379307792516182551");

    @Override
    public List<String> splitSecret(Integer k, Integer n, String secret) {
        if (k == null) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'k' is NULL");
        }
        if (n == null) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'n' is NULL");
        }
        if (secret == null) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'secret' is NULL");
        }
        if (k > n) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'k' is greater than 'n'");
        }
        if (BigInteger.valueOf(n).compareTo(DEFAULT_MOD_ARITH) > 0) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'n' is greater than modular arithmetic value");
        }
        if (new BigInteger(secret.getBytes()).compareTo(DEFAULT_MOD_ARITH) > 0) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'secret' is greater than modular arithmetic value");
        }

        // Initialization of polynomial coefficients and modular arithmetic
        BigInteger[] polynomialCoefficients = new BigInteger[k];

        for (int i = 0; i < k; i++) {
            // Coefficient for point x = 0 is "the secret"
            if (i == 0) {
                polynomialCoefficients[i] = new BigInteger(secret.getBytes());
            } else {
                // BigInteger(int bitLength, int certainty, Random rnd)
                // Constructs a randomly uniformly distributed positive BigInteger that is probably prime,
                // with the specified bitLength.
                // In this case coefficients are 1536 bit primes
                polynomialCoefficients[i] = new BigInteger(1536, 1, new SecureRandom());
            }
        }

        // The shares are stored in a List<String> in Base64 format
        String share;
        List<String> shares = new ArrayList<>();

        BigInteger partialSum;

        for (int i = 0; i < n; i++) {
            partialSum = BigInteger.ZERO;

            for (int j = 0; j < polynomialCoefficients.length; j++) {
                if (j == 0) {
                    partialSum = partialSum.add(polynomialCoefficients[j]);
                } else {
                    partialSum = partialSum.add(polynomialCoefficients[j].multiply(BigInteger.valueOf(i + 1)).pow(j));
                }
            }
            share = "" + (i + 1) + ":" + (partialSum.mod(DEFAULT_MOD_ARITH)).toString();

            shares.add(Base64.encodeBase64String(share.getBytes()));

        }
        return shares;

    }

    @Override
    public List<String> splitSecret(Integer k, Integer n, String secret, BigInteger modArith) {
        if (k == null) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'k' is NULL");
        }
        if (n == null) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'n' is NULL");
        }
        if (secret == null) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'secret' is NULL");
        }
        if (modArith == null) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'modArith' is NULL");
        }
        if (k > n) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'k' is greater than 'n'");
        }
        if (BigInteger.valueOf(n).compareTo(modArith) > 0) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'n' is greater than modular arithmetic value");
        }
        if (new BigInteger(secret.getBytes()).compareTo(modArith) > 0) {
            throw new FrameworkException("Secret Sharing splitSecret parameter 'secret' is greater than modular arithmetic value");
        }

        // Initialization of polynomial coefficients and modular arithmetic
        BigInteger[] polynomialCoefficients = new BigInteger[k];

        for (int i = 0; i < k; i++) {
            // Coefficient for point x = 0 is "the secret"
            if (i == 0) {
                polynomialCoefficients[i] = new BigInteger(secret.getBytes());
            } else {
                // BigInteger(int bitLength, int certainty, Random rnd)
                // Constructs a randomly uniformly distributed positive BigInteger that is probably prime,
                // with the specified bitLength.
                // In this case coefficients are 1536 bit primes
                polynomialCoefficients[i] = new BigInteger(1536, 1, new SecureRandom());
            }
        }

        // The shares are stored in a List<String> in Base64 format
        String share;
        List<String> shares = new ArrayList<>();

        BigInteger partialSum;

        for (int i = 0; i < n; i++) {
            partialSum = BigInteger.ZERO;

            for (int j = 0; j < polynomialCoefficients.length; j++) {
                if (j == 0) {
                    partialSum = partialSum.add(polynomialCoefficients[j]);
                } else {
                    partialSum = partialSum.add(polynomialCoefficients[j].multiply(BigInteger.valueOf(i + 1)).pow(j));
                }
            }
            share = "" + (i + 1) + ":" + (partialSum.mod(modArith)).toString();
            shares.add(Base64.encodeBase64String(share.getBytes()));
        }
        return shares;
    }

    @Override
    public String recoverSecret(List<String> shares, Integer k, Integer n) {
        if (k == null) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter 'k' is NULL");
        }
        if (n == null) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter 'n' is NULL");
        }
        if (shares == null) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter  list of 'shares' is NULL");
        }
        if (shares.isEmpty()) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter list of 'shares' is EMPTY ");
        }
        Integer t = shares.size();
        if (t < k) {
            throw new FrameworkException("Secret Sharing recoverSecret insufficient shares to recover secret");
        }

        Integer[] sharesIndexes = new Integer[t];
        BigInteger[] sharesValues = new BigInteger[t];
        // construct sharesIndexes-Values pass by reference
        parseShares(shares, sharesIndexes, sharesValues);

        BigInteger dividend, divider, partial, partialMult;
        BigInteger partialSecret = BigInteger.ZERO;

        for (int i = 0; i < t; i++) {

            dividend = BigInteger.ONE;
            divider = BigInteger.ONE;

            for (int j = 0; j < n; j++) {

                if (j != (sharesIndexes[i] - 1)) {

                    if (isInArray(sharesIndexes, j)) {

                        dividend = dividend.multiply(BigInteger.valueOf((-(j + 1))));
                        divider = divider.multiply(BigInteger.valueOf(sharesIndexes[i] - (j + 1)));

                    }
                }
            }
            // modular arithmetic
            dividend = dividend.mod(DEFAULT_MOD_ARITH);
            divider = divider.mod(DEFAULT_MOD_ARITH);

            partialMult = divider.modInverse(DEFAULT_MOD_ARITH);
            partialMult = partialMult.multiply(dividend);
            partialMult = partialMult.mod(DEFAULT_MOD_ARITH);

            partial = partialMult.multiply(sharesValues[i]);

            partialSecret = partialSecret.add(partial);

        }

        return new String(partialSecret.mod(DEFAULT_MOD_ARITH).toByteArray());

    }

    @Override
    public String recoverSecret(List<String> shares, Integer k, Integer n, BigInteger modArith) {
        if (k == null) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter 'k' is NULL");
        }
        if (n == null) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter 'n' is NULL");
        }
        if (modArith == null) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter 'modArith' is NULL");
        }
        if (shares == null) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter  list of 'shares' is NULL");
        }
        if (shares.isEmpty()) {
            throw new FrameworkException("Secret Sharing recoverSecret parameter list of 'shares' is EMPTY ");
        }
        Integer t = shares.size();
        if (t < k) {
            throw new FrameworkException("Secret Sharing recoverSecret insufficient shares to recover secret");
        }

        Integer[] sharesIndexes = new Integer[t];
        BigInteger[] sharesValues = new BigInteger[t];

        // construct sharesIndexes-Values pass by reference
        parseShares(shares, sharesIndexes, sharesValues);

        BigInteger dividend, divider, partial, partialMult;
        BigInteger partialSecret = BigInteger.ZERO;

        for (int i = 0; i < t; i++) {

            dividend = BigInteger.ONE;
            divider = BigInteger.ONE;

            for (int j = 0; j < n; j++) {

                if (j != (sharesIndexes[i] - 1)) {

                    if (isInArray(sharesIndexes, j)) {

                        dividend = dividend.multiply(BigInteger.valueOf((-(j + 1))));
                        divider = divider.multiply(BigInteger.valueOf(sharesIndexes[i] - (j + 1)));

                    }
                }
            }
            // modular arithmetic
            dividend = dividend.mod(modArith);
            divider = divider.mod(modArith);

            partialMult = divider.modInverse(modArith);
            partialMult = partialMult.multiply(dividend);
            partialMult = partialMult.mod(modArith);

            partial = partialMult.multiply(sharesValues[i]);

            partialSecret = partialSecret.add(partial);

        }
        return new String(partialSecret.mod(modArith).toByteArray());

    }

    private static void parseShares(List<String> shares, Integer[] sharesIndexes, BigInteger[] sharesValues) {

        String decodedShares;
        for (int i = 0; i < shares.size(); i++) {

            decodedShares = new String(Base64.decodeBase64(shares.get(i)));

            String[] shareIndexValue = decodedShares.split(":");

            try {
                sharesIndexes[i] = Integer.valueOf(shareIndexValue[0]);
                sharesValues[i] = new BigInteger("" + shareIndexValue[1]);
            } catch (NumberFormatException ex) {
                throw new FrameworkException("Secret Sharing error parsing shares", ex);
            }
        }
    }

    private static boolean isInArray(Integer[] indexes, int j) {

        for (int it = 0; it < indexes.length; it++) {
            if ((indexes[it] - 1) == j) {
                return true;
            }
        }
        return false;
    }

}
