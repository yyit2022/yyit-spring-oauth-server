package com.yyit.oauth.server;


import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64Tests {

    @Test
    void base64Test(){
        System.out.println(    Base64.getEncoder().encodeToString("yyit:123456".getBytes(StandardCharsets.UTF_8)));

    }
}
