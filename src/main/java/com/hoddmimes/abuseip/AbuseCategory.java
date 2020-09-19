package com.hoddmimes.abuseip;


public enum AbuseCategory{
    SSH("18,22","ssh"),
    WEB("18,21","apache-noscript") ,
    MAIL("18,11","smtp"),
    DOVECOT( "18,11","dovecot");

    private String mAbuseIpCat;
    private String mBadIpCat;
    AbuseCategory(String pAbuseIpCat, String pBadIpCat)
    {
        this.mAbuseIpCat = pAbuseIpCat;
        this.mBadIpCat = pBadIpCat;

    }

    public String getAbuseIpCat(){
        return mAbuseIpCat;
    }
    public String getBadIpCat(){
        return mBadIpCat;
    }
}

