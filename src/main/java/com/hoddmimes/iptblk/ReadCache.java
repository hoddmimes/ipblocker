package com.hoddmimes.iptblk;

import java.text.SimpleDateFormat;
import java.util.LinkedList;

public class ReadCache
{
    LinkedList<String>      mCache;
    int                     mCacheSize;

    ReadCache( int pSize )
    {
        mCache = new LinkedList<>();
        mCacheSize = pSize;
    }

    void add( String pLine ) {
        mCache.addFirst( pLine );
        if (mCache.size() > mCacheSize) {
            mCache.removeLast();
        }
    }

    String getCurrentLine() {
        return mCache.getFirst();
    }

    boolean findPattern(MailPattern pMailPattern, String pQID ) {
        for( String s : mCache ) {
            if (pMailPattern.match( s )) {
                if ((pQID == null) || ((pQID != null) && (pMailPattern.compareQID(pQID)))) {
                    return true;
                }
            }
        }
        return false;
    }

    void dump() {
        for( String s : mCache ) {
          System.out.println( s );
        }
    }

    public static void main(String[] args ) {
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");
        ReadCache c = new ReadCache( 5 );
        for( int i = 0; i < 7; i++ ) {
            String tStr = "Index : " + i + " time: " + sdf.format( System.currentTimeMillis());
            c.add( tStr );
            try{ Thread.sleep( 1000L );}
            catch( InterruptedException e) {}
        }
        c.dump();
    }
}
