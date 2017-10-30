/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jema.jwt;

import com.google.gson.JsonObject;
import com.jema.validation.FactoryJWT;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author MANUEL ALEJANDRO ALCALA BUSTOS
 */
public class BuilderImpl extends FactoryJWT {

    private final String keyPrivate;
    private final String keyPublic;
    private final int typeEncoding;
    private JsonObject jsonPayLoad;
    private JsonObject jsonHeader;

    public BuilderImpl(String keyPrivate, String keyPublic, int typeEncoding) {
        super();
        this.keyPrivate = keyPrivate;
        this.keyPublic = keyPublic;
        this.typeEncoding = typeEncoding;
    }

    /**
     *
     * @return @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    @Override
    public String getToken() {
        String token = null;
        try {
            String header = mapHeader.toString().replace("=", ":");
            String payload = mapPayLoad.toString().replace("=", ":");
            String temp = Base64.getUrlEncoder().encodeToString(header.getBytes("UTF-8")) + "." + Base64.getUrlEncoder().encodeToString(payload.getBytes("UTF-8"));
            switch (typeEncoding) {
                case 1: {
                    token = temp + "." + getTokenHMACSHA256(temp, this.keyPrivate);
                    break;
                }
                case 2: {
                    token = temp + "." + getTokenRS256(temp, this.keyPrivate);
                    break;
                }

            }

        } catch (InvalidKeyException | NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeySpecException | SignatureException ex) {
            Logger.getLogger(BuilderImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return token;
    }

    /**
     *
     * @param token
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    @Override
    public boolean validateToken(String token) {
//        boolean avalible = false;
//        JsonObject jsonPay = null;
//        JsonObject jsonHead = null;
//        String[] partToken = token.split("\\.");
//        String header = partToken[0];
//        String payload = partToken[1];
//        String signature = partToken[2];
//        String temp = header + "." + payload;
//        try {
//            Mac sha256_HMAC = Mac.getInstance(typeEncoding);
//            SecretKeySpec secret_key = new SecretKeySpec(keyPrivate.getBytes("UTF-8"), typeEncoding);
//            sha256_HMAC.init(secret_key);
//            String sign = Base64.getUrlEncoder().encodeToString(sha256_HMAC.doFinal(temp.getBytes("UTF-8")));
//            if (sign.equals(signature)) {
//                jsonPay = getJSONObject(new String(Base64.getUrlDecoder().decode(payload), "UTF-8"));
//                jsonHead = getJSONObject(new String(Base64.getUrlDecoder().decode(header), "UTF-8"));
//                if (jsonPay.has("exp")) {
//                    if (validateExp(jsonPay.get("exp").getAsLong())) {
//                        avalible = true;
//                    } else {
//                        avalible = false;
//                    }
//                } else {
//                    avalible = true;
//                }
//            }
//        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException ex) {
//            Logger.getLogger(BuilderImpl.class.getName()).log(Level.SEVERE, null, ex);
//        } finally {
//            if (avalible) {
//                this.jsonHeader = jsonHead;
//                this.jsonPayLoad = jsonPay;
//            }
//
//        }
//
//        return avalible;
        return false;
    }

    @Override
    public JsonObject getJsonPayLoad() {
        return jsonPayLoad;
    }

    @Override
    public JsonObject getJsonHeader() {
        return jsonHeader;
    }
}
