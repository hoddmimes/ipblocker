package com.hoddmimes.abuseip;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;


public class AbuseIP
{

    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private static final String DB_NAME = "abuseip.json";
    private static final String ABUSEIP_APIKEY_FILE = "abuseip-apikey.txt";
    private ArrayList<AbuseEntry> mAbuseList;
    private HashMap<AbuseCategory, Long> mCategoryTimeStamp;
    private long mLastReportTime;

    private String mAbuseIpApiKey = null;
    private long mReportingInterval;
    private boolean mBulkRepoting = false;
    private boolean mVerbose;
    private int mReported = 0;
    private int mTotalReported = 0;

    public AbuseIP( boolean pBulkReporting, long pReportingInterval, boolean pVerbose ) {
        mBulkRepoting = pBulkReporting;
        mReportingInterval = pReportingInterval;
        mAbuseList = new ArrayList<>();
        mCategoryTimeStamp = new HashMap<>();
        mLastReportTime = 0L;
        mVerbose = pVerbose;
        loadDB();
        loadAbuseIpApiKey();
    }



    private void log( String pMsg ) {
        System.out.println( SDF.format( System.currentTimeMillis()) + " " + pMsg );
    }

    private void logv( String pMsg ) {
        if (mVerbose) {
            log( "abuse-ip-dbg: " + pMsg );
        }
    }

    private void loadAbuseIpApiKey() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(ABUSEIP_APIKEY_FILE));
            for(String tLine; (tLine = br.readLine()) != null; )
            {
                if ((tLine.length() > 0) && (!tLine.startsWith("#")) && (mAbuseIpApiKey == null)) {
                    mAbuseIpApiKey = tLine.trim();
                    break;
                }
            }
            br.close();
        }
        catch( Exception e ) {
            e.printStackTrace();
        }
    }

    public void report(String pIpAddress, AbuseCategory pCategory, String pComment, long pAbuseLogTime ) {
        Long tLastTimestamp = mCategoryTimeStamp.get( pCategory );
        logv( "Reporting ip: " + pIpAddress + " category: " + pCategory.toString() + " comment: " + washComment( pComment ));


        if ((tLastTimestamp != null) && (tLastTimestamp >= pAbuseLogTime)) {
            return;
        }

        mCategoryTimeStamp.put( pCategory, pAbuseLogTime );

        mReported++;
        mTotalReported++;
        if (mBulkRepoting) {
            mAbuseList.add( new AbuseEntry( pIpAddress, pCategory, pComment ));
        } else {
            doEndreportingAbuseIp( pIpAddress, pCategory, pComment);
            doEndReportingBadIp( pIpAddress, pCategory, pComment );
        }
    }


    private String washComment( String pComment) {
        if (pComment == null) {
            return null;
        }

        return pComment.replace("hoddmimes","wonderland").replace("11721","1001001");
    }

    private void doEndReportingBadIp( String pIpAddress, AbuseCategory pCategory, String pComment ) {
        String tURL = "https://www.badips.com/add/" + pCategory.getBadIpCat() +"/" + pIpAddress;



        try {
            CloseableHttpClient tClient = HttpClients.createDefault();
            HttpGet tRequest = new HttpGet( tURL );

            tRequest.addHeader("Accept", "application/json");

            HttpResponse tResponse = tClient.execute( tRequest );
            if (tResponse.getEntity() != null) {
                HttpEntity tResponseEntity = tResponse.getEntity();
                int tStatus = (tResponse.getStatusLine() != null) ? tResponse.getStatusLine().getStatusCode() : 0;

                String tJsonResponse = EntityUtils.toString(tResponseEntity, StandardCharsets.UTF_8);
                log("badip-end-reporting status: " + tStatus + " response: " + tJsonResponse);
                /* if (tJsonResponse != null)
                {
                    JsonElement tElement  = JsonParser.parseString( tJsonResponse );
                    if (tElement != null) {
                        //{"err":"","suc":"increased report count for 37.123.157.199 on 176.26.166.66 in category ssh"}
                        System.out.println( tElement.toString() );
                    }
                }*/
            }
        }
        catch( Exception e) {
            e.printStackTrace();
        }
    }

    private void doEndreportingAbuseIp( String pIpAddress, AbuseCategory pCategory, String pComment ) {
        String tURL = "https://api.abuseipdb.com/api/v2/report";



        try {
            CloseableHttpClient tClient = HttpClients.createDefault();
            HttpPost tRequest = new HttpPost( tURL );

            tRequest.addHeader("Key", mAbuseIpApiKey);
            tRequest.addHeader("Accept", "application/json");

            List<NameValuePair> tParams = new ArrayList<>();
            tParams.add(new BasicNameValuePair("ip", pIpAddress));
            tParams.add(new BasicNameValuePair("categories", pCategory.getAbuseIpCat()));
            tParams.add(new BasicNameValuePair("comment", washComment( pComment )));

            tRequest.setEntity(new UrlEncodedFormEntity(tParams, StandardCharsets.UTF_8));
            HttpResponse tResponse = tClient.execute( tRequest );
            if (tResponse.getEntity() != null) {
                HttpEntity tResponseEntity = tResponse.getEntity();
                int tStatus = (tResponse.getStatusLine() != null) ? tResponse.getStatusLine().getStatusCode() : 0;

                String tJsonResponse = EntityUtils.toString(tResponseEntity, StandardCharsets.UTF_8);
                log("abuseip-end-reporting status: " + tStatus + " response: " + tJsonResponse);
                /* if (tJsonResponse != null)
                {
                    JsonElement tElement  = JsonParser.parseString( tJsonResponse );
                    if (tElement != null) {
                        //{"data":{"ipAddress":"127.0.0.137","abuseConfidenceScore":0}}
                        System.out.println( tElement.toString() );
                    }
                }*/
            }
        }
        catch( Exception e) {
            e.printStackTrace();
        }
    }



    public void doAbuseBulkReporting() {
        if (!mBulkRepoting) {
            return;
        }

        long tTimeDiff = System.currentTimeMillis() - mLastReportTime;
        if (tTimeDiff > mReportingInterval) {
            SimpleDateFormat tSDF = new SimpleDateFormat("yyMMdd-HHmm");
            String tFilename = "AbuseIpReport-" + tSDF.format( System.currentTimeMillis()) + ".csv";
            createReport( tFilename );
            mLastReportTime = System.currentTimeMillis();
            //SendReport to AbuseIp.com
            sendBulkReport( tFilename );
            // Clear Database
            mAbuseList.clear();
        }
    }


    private void sendBulkReport(String pFilename ) {
        String tURL = "https://104.31.75.222/api/v2/bulk-report";


        File tFile = new File( pFilename );
        String tBoundary ="--------------" + Long.toHexString( System.currentTimeMillis());

        MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
        entityBuilder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
        entityBuilder.setBoundary( tBoundary );
        entityBuilder.addPart("csv", new FileBody(tFile, ContentType.APPLICATION_OCTET_STREAM));

        try {

            CloseableHttpClient tClient = HttpClients.createDefault();
            HttpPost tRequest = new HttpPost( tURL );
            tRequest.setHeader("Key", mAbuseIpApiKey);
            tRequest.setHeader("Accept", "application/json");
            tRequest.setHeader("Accept-Encoding", "identity'");
            tRequest.setEntity(entityBuilder.build());

            HttpResponse tResponse = tClient.execute( tRequest );
            if (tResponse.getEntity() != null) {
                HttpEntity tResponseEntity = tResponse.getEntity();
                int tStatus = (tResponse.getStatusLine() != null) ? tResponse.getStatusLine().getStatusCode() : 0;

                String tJsonResponse = EntityUtils.toString(tResponseEntity, StandardCharsets.UTF_8);
                log("abuseip-bulk-reporting status: " + tStatus + " response: " + tJsonResponse );
                /*if (tJsonResponse != null)
                {
                    JsonElement tElement  = JsonParser.parseString( tJsonResponse );
                    if (tElement != null) {
                        System.out.println( tElement.toString() );
                    }
                }*/
            }
        }
        catch(Exception e ) {
            e.printStackTrace();
        }
    }

    private void createReport(String pFilename) {
       // Create AbuseIP CVS reporting file
        try {
            PrintWriter fp = new PrintWriter( new FileWriter( pFilename ));
            fp.println("IP,Categories,ReportDate,Comment");
            for( AbuseEntry tEntry : mAbuseList) {
              fp.println( tEntry.toCVS() );
            }
            fp.flush();
            fp.close();
        }
        catch( Exception e) {
            e.printStackTrace();
        }
    }

    private boolean withinReportingInterval( AbuseEntry pEntry ) {
        if (pEntry.mTime > (System.currentTimeMillis() - mReportingInterval)) {
            return true;
        }
        return false;
    }

    public void saveDB() {
        try {
            FileWriter tOut = new FileWriter( DB_NAME );
            JsonObject tRoot = new JsonObject();

            tRoot.addProperty("lastReport", SDF.format( mLastReportTime ));
            tRoot.addProperty("totalReported", mTotalReported);

            // Dump Category timestamps
            JsonArray jCategoryTimestamps = new JsonArray();
            for( AbuseCategory tCategory : mCategoryTimeStamp.keySet()) {
                JsonObject jObject = new JsonObject();
                jObject.addProperty( "category", tCategory.toString());
                jObject.addProperty( "timeStamp", mCategoryTimeStamp.get( tCategory ));
                jCategoryTimestamps.add(jObject);
            }
            tRoot.add("categories", jCategoryTimestamps );

            // Dump Abuse Entries
            JsonArray jEntries = new JsonArray();
            for( AbuseEntry tEntry : mAbuseList) {
                jEntries.add( tEntry.toJson());
            }
            tRoot.add("abuseEntries", jEntries );


            tOut.write( tRoot.toString() );
            tOut.flush();
            tOut.close();
            log("Saved " + mAbuseList.size() + " to ( " + DB_NAME + " ) abuse reported this run: " + mReported + " total reported: " + mTotalReported);
        }
        catch( Exception e ) {
            e.printStackTrace();
        }
    }

    private void loadDB() {
        try {
            mLastReportTime = System.currentTimeMillis();

            File tFile = new File( DB_NAME );
            if ( tFile.canRead() ) {
                JsonObject tRoot = JsonParser.parseReader( new FileReader( DB_NAME )).getAsJsonObject();

               try {
                       mLastReportTime = SDF.parse( tRoot.get("lastReport").getAsString()).getTime();
                       if (tRoot.has("totalReported")) {
                           mTotalReported = tRoot.get("totalReported").getAsInt();
                       }
               }
               catch( Exception e ) {
                   e.printStackTrace();
               }

                // Parse Abuse Categories
                mCategoryTimeStamp = new HashMap<>();
                JsonArray jCategoryTimestamps = tRoot.get("categories").getAsJsonArray();
                for( int i = 0; i < jCategoryTimestamps.size(); i++) {
                    JsonObject jObj = jCategoryTimestamps.get(i).getAsJsonObject();
                    mCategoryTimeStamp.put( AbuseCategory.valueOf(jObj.get("category").getAsString()), jObj.get("timeStamp").getAsLong());
                }

                JsonArray jEntries = tRoot.get("abuseEntries").getAsJsonArray();
                for( int i = 0; i < jEntries.size(); i++ ) {
                    AbuseEntry tAbuseEntry = new AbuseEntry( jEntries.get(i).getAsJsonObject() );
                    if (withinReportingInterval( tAbuseEntry )) {
                        mAbuseList.add( tAbuseEntry );
                    }
                }
                log("loaded " + mAbuseList.size() + " from Abuse DB ( " + DB_NAME + " )");
            } else {
                log("Abuse DB ( " + DB_NAME + " ) does not exists" );
            }
        }
        catch( Exception e) {
            e.printStackTrace();
        }
    }
}
