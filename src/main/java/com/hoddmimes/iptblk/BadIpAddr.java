package com.hoddmimes.iptblk;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.text.ParseException;
import java.text.SimpleDateFormat;

public class BadIpAddr {
        private static final SimpleDateFormat SDFTIME = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        private String      mIpAddr;
        private long        mActionTime;
        private boolean     mNew;
        private String      mService;

        public BadIpAddr( String pIpAddr, String pTimeStr, boolean pNew, String pService ) {
            try {mActionTime = SDFTIME.parse( pTimeStr ).getTime(); }
            catch( ParseException e) { e.printStackTrace();}
            mIpAddr = pIpAddr;
            mService = pService;
            mNew = pNew;
        }

        public BadIpAddr( String pJsonString) {
            JsonObject jsonObject = new JsonParser().parse(pJsonString).getAsJsonObject();
            mIpAddr = jsonObject.get("ipAddr").getAsString();
            mActionTime = jsonObject.get("actionTime").getAsLong();
            mNew = jsonObject.get("new").getAsBoolean();
            mService = jsonObject.get("service").getAsString();
        }

        public void updateTime( String pTimeStr ) {
            try {mActionTime = SDFTIME.parse( pTimeStr ).getTime(); }
            catch( ParseException e) { e.printStackTrace();}
        }


        public long getTimeSinceLastActionMs() {
            return System.currentTimeMillis() - mActionTime;
        }

        public boolean isNew() {
            return mNew;
        }

        public void setNew( boolean b) {
            mNew = b;
        }

        public String getIpAddr() {
            return mIpAddr;
        }

        public String getLastActionTime() {
            return SDFTIME.format( mActionTime );
        }

        public String toString() {
            return String.format("ip-addr: |%-15s| action-time: %s new: |%-5s| service: %s ", mIpAddr, SDFTIME.format(mActionTime), String.valueOf(mNew), mService);
        }


        public String jsonEncode() {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("ipAddr", mIpAddr);
            jsonObject.addProperty("actionTime", mActionTime);
            jsonObject.addProperty("new", mNew);
            jsonObject.addProperty("service", mService);
            return jsonObject.toString();
        }

}
