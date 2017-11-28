package com.secretsharing;

import com.secretsharing.exceptions.FrameworkException;
import java.math.BigInteger;
import java.util.List;

/**
 *
 * @author apeixinho
 */
public interface SecretSharingManager {

    public List<String> splitSecret(Integer k, Integer n, String secret) throws FrameworkException;

    public List<String> splitSecret(Integer k, Integer n, String secret, BigInteger modArith) throws FrameworkException;

    public String recoverSecret(List<String> shares, Integer k, Integer n) throws FrameworkException;

    public String recoverSecret(List<String> shares, Integer k, Integer n, BigInteger modArith) throws FrameworkException;

}
