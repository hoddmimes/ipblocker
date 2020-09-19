package com.hoddmimes.abuseip;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;

public class AbuseEntry
{
    public static  enum CATEGORY {};
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:hh:mm.SSS");
    private static final String C_IPADDRESS = "ipAddress";
    private static final String C_CATEGORY = "category";
    private static final String C_COMMENT = "comment";
    private static final String C_TIME = "time";


    String          mIpAddress;
    AbuseCategory   mCategory;
    long            mTime;
    String          mComment;


    public AbuseEntry( String pIpAddress, AbuseCategory pCategory, String pComment  ) {
        mIpAddress = pIpAddress;
        mCategory = pCategory;
        mTime = System.currentTimeMillis();
        mComment = pComment;
    }


    public AbuseEntry(JsonObject  jEntry  ) {
        this.mIpAddress = jEntry.get( C_IPADDRESS ).getAsString();
        this.mTime = stringToTime( jEntry.get( C_TIME ).getAsString());
        this.mComment = jEntry.get( C_COMMENT ).getAsString();
        this.mCategory = AbuseCategory.valueOf( jEntry.get( C_CATEGORY ).getAsString() );
    }

    public JsonObject toJson() {
        JsonObject jEntry = new JsonObject();
        jEntry.addProperty( C_IPADDRESS, this.mIpAddress);
        jEntry.addProperty( C_TIME, SDF.format(this.mTime));
        jEntry.addProperty( C_COMMENT, this.mComment);
        jEntry.addProperty( C_CATEGORY, this.mCategory.toString());
        return jEntry;
    }

    public String toISO8601Time( long pTime ) {
        DateFormat tFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
        return tFormat.format( pTime );
    }

    public String toCVS() {
        StringBuilder sb = new StringBuilder();
        sb.append( this.mIpAddress );
        sb.append( ", \"" + this.mCategory.getAbuseIpCat() + "\"");
        sb.append( ", " + toISO8601Time( this.mTime ));
        sb.append( ", \"" + this.mComment + "\"");
        return sb.toString();
    }






    private long stringToTime( String pTimeString ) {
        try {
            return SDF.parse(pTimeString).getTime();
        }
        catch( Exception e) {
            e.printStackTrace();
            return 0L;
        }
    }
}
