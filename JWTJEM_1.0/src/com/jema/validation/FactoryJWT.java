/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jema.validation;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.jema.jwt.BuilderJWT;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.rsa.RSAKeyFactory;
import sun.security.rsa.RSAPrivateCrtKeyImpl;

/**
 *
 * @author ALEJO
 */
public abstract class FactoryJWT implements BuilderJWT {

    protected final Map<String, Object> mapHeader;
    protected final Map<String, Object> mapPayLoad;

    public FactoryJWT() {
        this.mapHeader = new HashMap();
        this.mapPayLoad = new HashMap();
    }

    @Override
    public abstract String getToken();

    @Override
    public abstract boolean validateToken(String token);

    @Override
    public BuilderJWT addElementToHeader(String ref, String val) {
        mapHeader.put("\"" + ref + "\"", "\"" + val + "\"");
        return this;
    }

    @Override
    public BuilderJWT addElementToPayLoad(String ref, String val) {
        mapPayLoad.put("\"" + ref + "\"", "\"" + val + "\"");
        return this;
    }

    @Override
    public BuilderJWT addElementToHeader(String ref, boolean val) {
        mapHeader.put("\"" + ref + "\"", val);
        return this;
    }

    @Override
    public BuilderJWT addElementToPayLoad(String ref, boolean val) {
        mapPayLoad.put("\"" + ref + "\"", val);
        return this;
    }

    @Override
    public BuilderJWT addElementToHeader(String ref, int val) {
        mapHeader.put("\"" + ref + "\"", val);
        return this;
    }

    @Override
    public BuilderJWT addElementToPayLoad(String ref, int val) {
        mapPayLoad.put("\"" + ref + "\"", val);
        return this;
    }

    @Override
    public BuilderJWT addElementToHeader(String ref, double val) {
        mapHeader.put("\"" + ref + "\"", val);
        return this;
    }

    @Override
    public BuilderJWT addElementToPayLoad(String ref, double val) {
        mapPayLoad.put("\"" + ref + "\"", val);
        return this;
    }

    @Override
    public BuilderJWT addElementToHeader(String ref, long val) {
        mapHeader.put("\"" + ref + "\"", val);
        return this;
    }

    @Override
    public BuilderJWT addElementToPayLoad(String ref, long val) {
        mapPayLoad.put("\"" + ref + "\"", val);
        return this;
    }

    public JsonObject getJSONObject(String json) {
        JsonParser parser = new JsonParser();
        return parser.parse(json).getAsJsonObject();
    }

    protected boolean validateExp(long timeExp) {
        System.out.println("Tiempo Expiracion:" + timeExp);
        boolean validate = false;
        long currentTime = System.currentTimeMillis();
        if (timeExp > currentTime) {
            validate = true;
        }
        return validate;
    }

    @Override
    public abstract JsonObject getJsonPayLoad();

    @Override
    public abstract JsonObject getJsonHeader();

    protected String getTokenHMACSHA256(String content, String secret) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        return Base64.getUrlEncoder().encodeToString(sha256_HMAC.doFinal(content.getBytes("UTF-8")));
    }

    protected String getTokenRS256(String content, String keyPrivate) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException, IOException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(depurationKey(keyPrivate));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        Signature privateSignature = Signature.getInstance("SHA256withRSA", new BouncyCastleProvider());
        privateSignature.initSign(kf.generatePrivate(spec));
        privateSignature.update(content.getBytes("UTF-8"));
        byte[] s = privateSignature.sign();
        return Base64.getEncoder().encodeToString(s);
    }

    private byte[] depurationKey(String key) throws UnsupportedEncodingException {
        String temp = new String(key);
        Pattern patron = Pattern.compile("(\\-.*\\-)");
        Matcher matcher = patron.matcher(key);
        while (matcher.find()) {
            temp = temp.replace(matcher.group(1), "");
        }
        temp = temp.trim();
        temp = temp.replace("\n", "");
        return DatatypeConverter.parseBase64Binary(temp);
    }
}
