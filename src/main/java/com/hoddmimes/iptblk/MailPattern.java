package com.hoddmimes.iptblk;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MailPattern
{
    static Pattern cAddrPattern = Pattern.compile("\\[(\\d+\\.\\d+\\.\\d+\\.\\d+)\\]");
    static Pattern cQidPattern = Pattern.compile("sendmail\\[\\d+\\]: (\\w+):");
    static Pattern cTimePattern = Pattern.compile("^(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+)");
    static Pattern cLogDatePattern = Pattern.compile("^(\\d+-\\d+-\\d+)");


    String mPatternString;
    Pattern mPattern;
    Matcher mMatcher;

    MailPattern( String pPatternString ) {
        mPatternString = pPatternString;
        mPattern = Pattern.compile(mPatternString);
        mMatcher = null;
    }


    boolean match( String pString ) {
        mMatcher = mPattern.matcher( pString );
        return mMatcher.matches();
    }

    Matcher getMatcher() {
        return mMatcher;
    }

    String getTime() {
       String tLine =  mMatcher.group(0);
        Matcher m = cTimePattern.matcher(tLine);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    boolean compareQID( String pQID ) {
        String tQID = this.getQID();
        if (tQID == null) {
            return false;
        }
        return (pQID.compareTo( tQID) == 0);
    }


    String getQID() {
        String tLine =  mMatcher.group(0);
        Matcher m = cQidPattern.matcher(tLine);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    String getIpAddr() {
        Matcher m = cAddrPattern.matcher( mMatcher.group(0));
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    String getString() {
        return mMatcher.group(0);
    }

    static String getLogDate( String pLine ) {
        Matcher m = cLogDatePattern.matcher( pLine );
        if (m.find()) {
            return m.group(1);
        }
        return "0000-00-00";
    }

    static String getQID( String pLine ) {
        Matcher m = cQidPattern.matcher( pLine );
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }
}
