/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jema.validation;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.jema.jwt.BuilderJWT;
import java.util.HashMap;
import java.util.Map;

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
        System.out.println("Tiempo Expiracion:"+timeExp);
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
}
