/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jema.jwt;

import com.google.gson.JsonObject;

/**
 *
 * @author ALEJO
 */
public interface BuilderJWT {

    public abstract String getToken();

    public abstract boolean validateToken(String token);

    public BuilderJWT addElementToHeader(String ref, String val);

    public BuilderJWT addElementToPayLoad(String ref, String val);

    public BuilderJWT addElementToHeader(String ref, boolean val);

    public BuilderJWT addElementToPayLoad(String ref, boolean val);

    public BuilderJWT addElementToHeader(String ref, int val);

    public BuilderJWT addElementToPayLoad(String ref, int val);

    public BuilderJWT addElementToHeader(String ref, double val);

    public BuilderJWT addElementToPayLoad(String ref, double val);

    public BuilderJWT addElementToHeader(String ref, long val);

    public BuilderJWT addElementToPayLoad(String ref, long val);

    public abstract JsonObject getJsonPayLoad();

    public abstract JsonObject getJsonHeader();

}
