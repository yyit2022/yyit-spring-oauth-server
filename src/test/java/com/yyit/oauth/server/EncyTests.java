package com.yyit.oauth.server;

import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.Base64;

/**
 * <p>
 * 此处为功能说明
 * </p>
 *
 * @author yanpingping
 * @date 2022/4/26
 **/
public class EncyTests {

    @Test
    void base64test(){
        String text = "yyitjava1:123";
        System.out.println(Base64.getEncoder().encodeToString(text.getBytes()));
    }

    @Test
    void urlEncodeTest(){
        String urlStr = "https://www.baidu.com";
        System.out.println(URLEncoder.encode(urlStr, Charset.defaultCharset()));
    }

}
