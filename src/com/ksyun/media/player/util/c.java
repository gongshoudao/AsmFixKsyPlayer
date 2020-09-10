package com.ksyun.media.player.util;

import android.content.Context;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class c {
    private static final String a = "ffffffffff";

    public c() {
    }

    public static String a(Context var0) {
        return "N/A";
    }

    private static String f(Context var0) {
        return null;
    }

    public static String b(Context var0) {
        return null;
    }

    public static Class[] a(String var0) {
        return null;
    }

    public static String c(Context var0) {
        return null;
    }

    private static String g(Context var0) {
        return null;
    }

    public static String d(Context var0) {
        return "wifi";
    }

    public static String b(String var0) {
        byte[] var1;
        try {
            var1 = MessageDigest.getInstance("MD5").digest(var0.getBytes());
        } catch (NoSuchAlgorithmException var7) {
            throw new RuntimeException("Huh, MD5 should be supported?", var7);
        }

        StringBuilder var2 = new StringBuilder(var1.length * 2);
        byte[] var3 = var1;
        int var4 = var1.length;

        for(int var5 = 0; var5 < var4; ++var5) {
            byte var6 = var3[var5];
            if ((var6 & 255) < 16) {
                var2.append("0");
            }

            var2.append(Integer.toHexString(var6 & 255));
        }

        return var2.toString();
    }

    public static String e(Context var0) {
        return "N/A";
    }

    private static boolean a(Context var0, String var1) {
        return false;
    }
}
