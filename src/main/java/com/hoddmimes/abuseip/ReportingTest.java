package com.hoddmimes.abuseip;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.apache.http.*;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;


public class ReportingTest
{
    private static final String ABUSEIP_APIKEY_FILE = "abuseip-apikey.txt";
    String mAbuseIpApiKey = null;

    public static void main(String args[] )
    {
        ReportingTest rt = new ReportingTest();
        rt.loadAbuseIpApiKey();
        rt.testEndpointReporting();
        //rt.testBulkReporting();
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

    private void testEndpointReporting() {
        String tURL = "https://api.abuseipdb.com/api/v2/report";

        try {
            CloseableHttpClient tClient = HttpClients.createDefault();
            HttpPost tRequest = new HttpPost( tURL );

            tRequest.addHeader("Key", mAbuseIpApiKey);
            tRequest.addHeader("Accept", "application/json");

            List<NameValuePair> tParams = new ArrayList<>();
            tParams.add(new BasicNameValuePair("ip", "127.0.0.137"));
            tParams.add(new BasicNameValuePair("categories", "18,21"));
            tParams.add(new BasicNameValuePair("comment", "Brute force"));

            tRequest.setEntity(new UrlEncodedFormEntity(tParams, StandardCharsets.UTF_8));
            HttpResponse tResponse = tClient.execute( tRequest );
            if (tResponse.getEntity() != null) {
                HttpEntity tResponseEntity = tResponse.getEntity();
                int tStatus = (tResponse.getStatusLine() != null) ? tResponse.getStatusLine().getStatusCode() : 0;

                String tJsonResponse = EntityUtils.toString(tResponseEntity, StandardCharsets.UTF_8);
                if (tJsonResponse != null)
                {
                    JsonElement tElement  = JsonParser.parseString( tJsonResponse );
                    if (tElement != null) {
                        //{"data":{"ipAddress":"127.0.0.137","abuseConfidenceScore":0}}
                        System.out.println( tElement.toString() );
                    }
                }
            }
        }
        catch( Exception e) {
            e.printStackTrace();
        }
    }



    private void testBulkReporting()
    {

        //String tURL = "http://api.abuseipdb.com/api/v2/bulk-report";
        String tURL = "https://104.31.75.222/api/v2/bulk-report";

        File tFile = new File("test.csv" );
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
                if (tJsonResponse != null)
                {
                    JsonElement tElement  = JsonParser.parseString( tJsonResponse );
                    if (tElement != null) {
                        System.out.println( tElement.toString() );
                    }
                }
            }
        }
        catch(Exception e ) {
            e.printStackTrace();
        }
    }
}
