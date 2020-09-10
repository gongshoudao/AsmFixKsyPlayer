package com.ksyun.media.player.misc;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;

import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class e
{
    private static e a;
    private static final String b = "ffffffffff";
    private String c;
    private String d;
    private String e;
    private String f;
    private Context g;

    public static e a()
    {
        synchronized (e.class)
        {
            if (a == null) {
                a = new e();
            }
            return a;
        }
    }

    public void a(Context paramContext)
    {
        this.g = paramContext;
    }

    public void a(String paramString1, String paramString2, String paramString3, String paramString4)
    {
        this.c = b(paramString1);
        this.d = b(paramString2);
        this.e = b(paramString3);
        this.f = b(paramString4);
    }

    public String b()
    {
        return this.c;
    }

    public String c()
    {
        return this.d;
    }

    public String d()
    {
        return this.e;
    }

    public String e()
    {
        return this.f;
    }

    public String f()
    {
        if (this.g == null) {
            return null;
        }
        StringBuilder localStringBuilder = new StringBuilder();

        localStringBuilder.append(this.g.getPackageName()).append(';').append(Build.VERSION.RELEASE).append(';').append(Build.MODEL);

        return b(localStringBuilder.toString());
    }

    public String g()
    {
        if (this.g == null) {
            return null;
        }
        String str1 = null;
        String str2 = h();
        if (TextUtils.isEmpty(str2)) {
            str2 = "ffffffffff";
        }
        String str3 = i();
        if (TextUtils.isEmpty(str3)) {
            str3 = "ffffffffff";
        }
        String str4 = k();
        if (TextUtils.isEmpty(str4)) {
            str4 = "ffffffffff";
        }
        str1 = str2 + "-" + a(new StringBuilder().append(str4).append(str3).toString());

        return b(str1);
    }

    public String a(String paramString)
    {
        byte[] arrayOfByte1;
        try
        {
            arrayOfByte1 = MessageDigest.getInstance("MD5").digest(paramString.getBytes());
        }
        catch (NoSuchAlgorithmException localNoSuchAlgorithmException)
        {
            throw new RuntimeException("Huh, MD5 should be supported?", localNoSuchAlgorithmException);
        }
        StringBuilder localStringBuilder = new StringBuilder(arrayOfByte1.length * 2);
        for (int k : arrayOfByte1)
        {
            if ((k & 0xFF) < 16) {
                localStringBuilder.append("0");
            }
            localStringBuilder.append(Integer.toHexString(k & 0xFF));
        }
        return localStringBuilder.toString();
    }

    private String b(String paramString)
    {
        if (TextUtils.isEmpty(paramString)) {
            return null;
        }
        try
        {
            String str = new String(paramString.getBytes(), "UTF-8");
            return URLEncoder.encode(str, "UTF-8");
        }
        catch (Exception localException) {}
        return null;
    }

    private String h()
    {
        return null;
    }

    private String i()
    {
        if (this.g == null) {
            return null;
        }
        return Settings.Secure.getString(this.g.getContentResolver(), "android_id");
    }

    private String j()
    {
        return null;
    }

    private String k()
    {
        return null;
    }

    private boolean c(String paramString)
    {
        if (this.g == null) {
            return false;
        }
        return this.g.checkCallingOrSelfPermission(paramString) == 0;
    }
}
