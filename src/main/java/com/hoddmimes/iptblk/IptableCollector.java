package com.hoddmimes.iptblk;


import com.hoddmimes.abuseip.AbuseCategory;
import com.hoddmimes.abuseip.AbuseIP;

import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IptableCollector
{
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd");
    private static final SimpleDateFormat SDFTIME = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");


    // 2019-08-11 01:04:52 hoddmimes sendmail[8767]: x7AN4lnx008767: [185.234.219.103] did not issue MAIL/EXPN/VRFY/ETRN during connection to MTA
    //  Unauthorized connection attempt
    MailPattern MX_UnAuthConnPattern_1 = new MailPattern("(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) \\w+ sendmail\\[\\d+\\]: \\w+: [^\\s]*\\s*\\[(\\d+\\.\\d+\\.\\d+\\.\\d+)\\] [\\(may be forged\\) ]*did not issue MAIL/EXPN/VRFY/ETRN during connection to MTA");


    //2019-09-21 09:13:15 hoddmimes sendmail[9671]: x8L7D8YA009671: ruleset=check_rcpt, arg1=<mail@bertilzon.com>, relay=46-120-251-9.static.012.net.il
    // [46.120.251.9] (may be forgeRelyingd), reject=550 5.7.1 <mail@bertilzon.com>... Relaying denied. IP name possibly forged [46.120.251.9]
    MailPattern MX_UnAuthConnPattern_2 = new MailPattern("(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) \\w+ sendmail\\[\\d+\\]: \\w+: .+ reject=.+Relaying denied.+");


    // 2019-08-12 13:30:45 hoddmimes sendmail[18994]: x7CBUc0i018991: to=bertilsson_mail, delay=00:00:01, xdelay=00:00:00, mailer=local, pri=203870, dsn=2.0.0, stat=Sent
    // Sent notification, linked to (prev) SenfFromPattern
    MailPattern MX_SentPattern = new MailPattern("(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) \\w+ sendmail\\[\\d+\\]: \\w+: .+ reject=.+Relaying denied.+");

    // 2019-08-11 23:06:55 hoddmimes sendmail[14209]: x7BL5tbV014209: ruleset=check_rcpt, arg1=<anna.bertilsson@bertilzon.com>, relay=186-249-231-162.centurytelecom.net.br [186.249.231.162] (may be forged), reject=550 5.7.1 <anna.bertilsson@bertilzon.com>... Mail from 186.249.231.162 refused - see http://www.barracudacentral.org/rbl/
    // Spam reject
    MailPattern MX_SpamRejectPattern = new MailPattern("(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) \\w+ sendmail\\[\\d+\\]: \\w+: .+ reject=550 .+ Mail from (\\d+\\.\\d+\\.\\d+\\.\\d+) refused .+");

    // 2019-08-11 12:25:57 hoddmimes sendmail[12085]: x7BAPo6j012085: kalle.kalle [77.40.2.16] (may be forged) did not issue MAIL/EXPN/VRFY/ETRN during connection to MSA
    // SSL reject
    MailPattern MX_SSLUnAuthConnPattern = new MailPattern("(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) \\w+ sendmail\\[\\d+\\]: .+: [^ ]*\\s?\\[(\\d+\\.\\d+\\.\\d+\\.\\d+)\\].+MSA");

    // 2020-05-03 00:53:36 hoddmimes sendmail[15354]: 042Mra6V015354: rejecting commands from zg-0428c-417.stretchoid.com [162.243.140.87] due to pre-greeting traffic after 0 seconds
    MailPattern MX_pre_greeting = new MailPattern("^(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) \\w+ sendmail\\[\\d+\\]: .+ \\[(\\d+\\.\\d+\\.\\d+\\.\\d+)\\] due to pre-greeting traffic after \\d+ seconds");




    ArrayList<String> mAllowedNodes = null;
    AbuseIP mAbuseIP = null;

    long mAbuseReportingInterval = (6L * 3600L * 1000L);
    long mBlackListTime = 60L * 60L * 1000L;
    String mScanDate = null;
    String mInMailLog = "/var/log/maillog";
    String mInSecureLog = "/var/log/secure";
    String mInHttpLog = "/var/log/http/hoddmimes_error_log";
    String mIpTableCmdFile = "iptables.cmd";
    String mOutFileDir = "./";
    String mRunDbFile = "IPTRUN.DB";
    boolean mCreateCmdFile = true;
    boolean mAbuseIpReporting = false;
    boolean mReset = true;
    boolean mVerbose = true;

    HashMap<String,BadIpAddr> mBadIpEntries = null;
    List<String> mIptablesCommands = null;




    public static void main( String[]  args)
    {
            long t1 = System.currentTimeMillis();

            IptableCollector bic = new IptableCollector();
            bic.parseArguments( args );
            bic.initialize();
            bic.process();
            bic.postProcess();

            System.out.println("[ Execution Time: " + (System.currentTimeMillis() - t1) + " ms. ]");
    }


    private void postProcess() {
        if (mAbuseIP != null) {
            mAbuseIP.doAbuseBulkReporting();
            mAbuseIP.saveDB();
        }

    }

    private void process() {

            mIptablesCommands = new ArrayList<>();
            mBadIpEntries = new HashMap<>();

            if (!mReset) {
                loadStateFromRunDb();
            }

            this.scan_secure_log();
            this.scan_mail_log();
            this.scan_http_log();
            this.analyze();
            this.writeCommandFile();

            this.saveStateToRunDb();
    }

    private void loadStateFromRunDb( ) {
        String tLine;
        int i = 0;

        File tFile = new File( mRunDbFile );
        if (tFile.exists()) {
            try {
                BufferedReader tReader = new BufferedReader(new FileReader(tFile));
                while ((tLine = tReader.readLine()) != null) {
                    BadIpAddr ipa = new BadIpAddr( tLine );
                    mBadIpEntries.put( ipa.getIpAddr(), ipa);
                    i++;
                }
                tReader.close();
                System.out.println("Loaded " + i + " IP address entries from RunDb ( " + mRunDbFile + " )");
            }
            catch( IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("RunDB ( " + mRunDbFile + " ) does not exists");
        }
    }

    private void saveStateToRunDb( ) {
        String tLine;

        File tFile = new File( mRunDbFile );

        try {
            PrintWriter tWriter = new PrintWriter(new FileOutputStream(tFile));
            for( BadIpAddr ipa : mBadIpEntries.values() ) {
                tWriter.println( ipa.jsonEncode() );
            }
            System.out.println("Saved " + mBadIpEntries.size() + " IP address entries to RunDb ( " + mRunDbFile + " )");
            tWriter.flush();
            tWriter.close();

        }
        catch( IOException e) {
            e.printStackTrace();
        }

    }


    private void initialize() {
        mScanDate = SDF.format( System.currentTimeMillis() );
        mBadIpEntries = new HashMap<>();

        if (mAbuseIpReporting) {
            mAbuseIP = new AbuseIP( false, mAbuseReportingInterval, mVerbose );
        }
    }


    private void writeCommandFile() {
        PrintWriter tOut, tTraceOut;
        File tOutFile = new File(   mIpTableCmdFile );
        File tTraceFile = new File( mOutFileDir + "iptable-cmd-history.log" );

        try {
            tOut = new PrintWriter( tOutFile );
            tTraceOut = new PrintWriter( new FileOutputStream( tTraceFile, true ));
            tOut.println("Time#" + SDFTIME.format( System.currentTimeMillis()));
            for( String s : mIptablesCommands ) {
                tOut.println( s );
                tTraceOut.println( SDFTIME.format( System.currentTimeMillis() ) + "  " +  s );
            }
            System.out.println( "\n" + mIptablesCommands.size() + " changes writen to \"" + mIpTableCmdFile + "\"\n");
            tTraceOut.flush();
            tTraceOut.close();

            tOut.flush();
            tOut.close();
        }
        catch( IOException e) {
            e.printStackTrace();
        }
    }

    private void analyze() {
        SimpleDateFormat tSDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        ArrayList<String> tTrcMsgs = new ArrayList<String>();
        List<BadIpAddr> tBadIpList = new ArrayList(mBadIpEntries.values());

        long tNow = System.currentTimeMillis();
        System.out.println("\n\nAnalyze at " + SDFTIME.format(tNow));
        for (BadIpAddr tEntry : tBadIpList) {
            if (!isAllowedNode( tEntry.getIpAddr() )) {
                long tInactTimeSec = (tNow - tEntry.getTimeSinceLastActionMs()) / 1000L;

                if (mVerbose) {
                    System.out.println( tEntry );
                }

                if (tEntry.isNew()) {
                    tTrcMsgs.add(tSDF.format(System.currentTimeMillis()) + "    ADD:  " + tEntry.getIpAddr());
                    mIptablesCommands.add("ADD#" + tEntry.getIpAddr());
                    tEntry.setNew(false);
                } else if (tEntry.getTimeSinceLastActionMs() > mBlackListTime) {
                    mBadIpEntries.remove(tEntry.getIpAddr());
                    mIptablesCommands.add("REMOVE#" + tEntry.getIpAddr());
                    tTrcMsgs.add(tSDF.format(System.currentTimeMillis()) + "    REMOVE:  " + tEntry.getIpAddr());
                };
            }
        }
    }

    private boolean isAllowedNode( String pIpAddr ) {

        if (pIpAddr.compareTo("127.0.0.1") == 0) {
            return true;
        }
       if (mAllowedNodes == null) {
           return false;
       }

       for( String tAddr : mAllowedNodes) {
           if (pIpAddr.startsWith( tAddr )) {
               return true;
           }
       }
       return false;
    }




    private void parseAllowedNodes( String pNodeList ) {
       //Remove leading and trailing quotes is presents
       String tNodes = pNodeList.trim();
       tNodes = tNodes.replace("\"","").replace(" ","");
       String[] tNodeArr = tNodes.split(",");
       for( int i = 0; i < tNodeArr.length; i++) {
           mAllowedNodes.add( tNodeArr[i]);
       }
    }

    private void parseArguments( String[] args ) {
        int i = 0;

        mAllowedNodes = new ArrayList<>();
        mAllowedNodes.add("192.168.42");

        while( i < args.length) {


            if (args[i].compareToIgnoreCase("-abuseReportingInterval") == 0) {
                mAbuseReportingInterval = Long.parseLong( args[i+1] )  * (3600L * 1000L);
                i++;
            }

            if (args[i].compareToIgnoreCase("-createCmd") == 0) {
                mCreateCmdFile =  Boolean.parseBoolean( args[i+1] );
                i++;
            }
            if (args[i].compareToIgnoreCase("-abuseIp") == 0) {
                mAbuseIpReporting =  Boolean.parseBoolean( args[i+1] );
                i++;
            }


            if (args[i].compareToIgnoreCase("-blacklistTime") == 0) {
                mBlackListTime =  Long.parseLong( args[i+1] ) * 60L * 1000L;
                i++;
            }

            if (args[i].compareToIgnoreCase("-cmdFile") == 0) {
                mIpTableCmdFile =  args[i+1];
                i++;
            }

            if (args[i].compareToIgnoreCase("-allowedNodes") == 0) {
                mAllowedNodes = new ArrayList<>();
                parseAllowedNodes( args[i+1] );
                i++;
            }

            if (args[i].compareToIgnoreCase("-verbose") == 0) {
                mVerbose =  Boolean.parseBoolean(args[i+1]);
                i++;
            }

            if (args[i].compareToIgnoreCase("-reset") == 0) {
                mReset =  Boolean.parseBoolean(args[i+1]);
                i++;
            }

            if (args[i].compareToIgnoreCase("-outDir") == 0) {
                mOutFileDir =  args[i+1];
                i++;

                if (!mOutFileDir.endsWith("/")) {
                    mOutFileDir = mOutFileDir + "/";
                }
            }
            if (args[i].compareToIgnoreCase("-maillog") == 0) {
                mInMailLog = args[i+1];
            }
            if (args[i].compareToIgnoreCase("-secure") == 0) {
                mInSecureLog = args[i+1];
            }
            if (args[i].compareToIgnoreCase("-httplog") == 0) {
                mInHttpLog = args[i+1];
                i++;
            }
            i++;
        }

        if (mReset) {
            System.out.println("   parameter \"verbose\" " + mVerbose);
            System.out.println("   parameter \"maillog\" " + mInMailLog);
            System.out.println("   parameter \"httplog\" " + mInHttpLog);
            System.out.println("   parameter \"outDir\" " + mOutFileDir);
            System.out.println("   parameter \"cmdFile\" " + mIpTableCmdFile);
            System.out.println("   parameter \"abuseReportingInterval\" " + (mAbuseReportingInterval/1000L) + " sec");
            System.out.println("   parameter \"createCmd\" " + mCreateCmdFile);
            System.out.println("   parameter \"abuseIp\" " + mAbuseIpReporting);
            System.out.println("   parameter \"blacklistTime\" " + mBlackListTime + "   " +
                    (mBlackListTime / 60000L) + " min   ( " + (mBlackListTime / 1000L) + " sec. )");
            System.out.println("   parameter \"reset\" " + mReset);
            System.out.println("   parameter \"allowedNodes\"");
            for( String tNode : mAllowedNodes) {
                System.out.println("   " + tNode );
            }
        }
    }

    private void scan_secure_log() {
        Pattern tLogDatePattern = Pattern.compile("^(\\d+-\\d+-\\d+)");
        Pattern tErrorPattern1 = Pattern.compile("^(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) .* Invalid user .* from (\\d+\\.\\d+\\.\\d+\\.\\d+) port \\d+");
        Pattern tErrorPattern2 = Pattern.compile("^(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) .* invalid user .* (\\d+\\.\\d+\\.\\d+\\.\\d+) port \\d+ \\[preauth\\]");
        Pattern tErrorPattern3 = Pattern.compile("^(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) .* pam_unix\\(dovecot:auth\\): authentication failure; .* rhost=(\\d+\\.\\d+\\.\\d+\\.\\d+)");


        mScanDate = SDF.format( System.currentTimeMillis());

        File tFile =  new File( mInSecureLog );
        BufferedReader tReader = null;
        String tLine = null; String tLogDate = null;
        int tFoundEntries = 0;

        try {
            tReader = new BufferedReader( new FileReader( tFile ));

            while ((tLine = tReader.readLine()) != null) {
                Matcher m = tLogDatePattern.matcher( tLine );
                tLogDate = (m.find()) ? m.group(1) : "";
                if (tLogDate.compareTo(mScanDate) == 0) {
                    m = tErrorPattern1.matcher( tLine );
                    if (m.matches()) {
                        String tTimeStr = m.group(1);
                        String tIpAddr = m.group(2);
                        updateIpEntries( tIpAddr, tTimeStr, AbuseCategory.SSH, tLine);
                        tFoundEntries++;
                    }
                    m = tErrorPattern2.matcher( tLine );
                    if (m.matches()) {
                        String tTimeStr = m.group(1);
                        String tIpAddr = m.group(2);
                        updateIpEntries( tIpAddr, tTimeStr, AbuseCategory.SSH, tLine);
                        tFoundEntries++;
                    }
                    m = tErrorPattern3.matcher( tLine );
                    if (m.matches()) {
                        String tTimeStr = m.group(1);
                        String tIpAddr = m.group(2);
                        updateIpEntries( tIpAddr, tTimeStr, AbuseCategory.DOVECOT, tLine);
                        tFoundEntries++;
                    }
                }
            }
            tReader.close();
            if (mVerbose) {
                System.out.println("=====          Scanned SECURE, " + tFoundEntries + " entries found");
            }
        }
        catch( IOException e) {
            e.printStackTrace();
        }
    }
    private void scan_http_log() {
        Pattern tLogDatePattern = Pattern.compile("^\\[(\\d+-\\d+-\\d+)");
        Pattern tErrorPattern1 = Pattern.compile("^\\[(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+)\\.\\d+\\] \\[error\\] .+ \\[client (\\d+\\.\\d+\\.\\d+\\.\\d+):\\d+\\] .+ script not found or unable to stat.*");
        //[2020-08-13 22:08:15.384580] [error] [pid 3492] mod_cgid.c(1077): [client 89.158.77.24:3920] AH01264: script not found or unable to stat: /var/www/cgi-bin/kerbynet
        mScanDate = SDF.format( System.currentTimeMillis());
        int tFoundEntries = 0;

        File tFile =  new File( mInHttpLog );
        BufferedReader tReader = null;
        String tLine = null; String tLogDate = null;

        try {
            tReader = new BufferedReader( new FileReader( tFile ));
            while ((tLine = tReader.readLine()) != null) {
                Matcher m = tLogDatePattern.matcher( tLine );
                tLogDate = (m.find()) ? m.group(1) : "";
                if (tLogDate.compareTo(mScanDate) == 0) {
                   m = tErrorPattern1.matcher( tLine );
                   if (m.matches()) {
                       String tTimeStr = m.group(1);
                       String tIpAddr = m.group(2);
                       updateIpEntries( tIpAddr, tTimeStr, AbuseCategory.WEB, tLine );
                       tFoundEntries++;
                   }
                }
            }
            tReader.close();
            if (mVerbose) {
                System.out.println("=====          Scanned HTTP, " +  tFoundEntries + " entries found");
            }
        }
        catch( IOException e) {
            e.printStackTrace();
        }
    }

    private void scan_mail_log() {
        mScanDate = SDF.format( System.currentTimeMillis());

        ReadCache tReadCache = new ReadCache( 20 );
        File tFile =  new File(mInMailLog);
        BufferedReader tReader = null;
        String tLine = null; String tLogDate = null;
        int tFoundEntries = 0;

        try {
            tReader = new BufferedReader( new FileReader( tFile ));

            while ((tLine = tReader.readLine()) != null) {
                tLogDate = MailPattern.getLogDate( tLine );
                if (tLogDate.compareTo(mScanDate) == 0) {
                    tReadCache.add( tLine );
                    if (scan_mail_log( tReadCache )) {
                        tFoundEntries++;
                    }
                }
            }
            if (mVerbose) {
                System.out.println("=====          Scanned MAIL, " +  tFoundEntries + " entries found");
            }
        }
        catch( IOException e) {
            e.printStackTrace();
        }
        if (tReader != null) {
            try {tReader.close();}
            catch( IOException e) {}
        }
    }

    private boolean scan_mail_log( ReadCache pReadCache ) {
        String tLine = pReadCache.getCurrentLine();


        if (MX_UnAuthConnPattern_1.match(tLine)) {
            String tIpAddr = MX_UnAuthConnPattern_1.getIpAddr();
            String tTimeStr = MX_UnAuthConnPattern_1.getTime();
            updateIpEntries(tIpAddr, tTimeStr, AbuseCategory.MAIL, tLine);
            return true;
        }
        else if (MX_UnAuthConnPattern_2.match(tLine)) {
            String  tIpAddr = MX_UnAuthConnPattern_2.getIpAddr();
            String tTimeStr = MX_UnAuthConnPattern_2.getTime();
            updateIpEntries( tIpAddr, tTimeStr, AbuseCategory.MAIL, tLine);
            return true;
        }
        else if (MX_SSLUnAuthConnPattern.match(tLine)) {
            String  tIpAddr = MX_SSLUnAuthConnPattern.getIpAddr();
            String tTimeStr = MX_SSLUnAuthConnPattern.getTime();
            updateIpEntries( tIpAddr, tTimeStr, AbuseCategory.MAIL, tLine);
            return true;
        } else if (MX_SpamRejectPattern.match(tLine)) {
            String tIpAddr = MX_SpamRejectPattern.getIpAddr();
            String tTimeStr =  MX_SpamRejectPattern.getTime();
            updateIpEntries( tIpAddr, tTimeStr, AbuseCategory.MAIL, tLine);
            return true;
        } else if (MX_pre_greeting.match(tLine)) {
            String tIpAddr = MX_pre_greeting.getIpAddr();
            String tTimeStr =  MX_pre_greeting.getTime();
            updateIpEntries( tIpAddr, tTimeStr, AbuseCategory.MAIL, tLine);
            return true;
        }
        return false;
    }

    private void updateIpEntries(String pIpAddr, String pTimeStr, AbuseCategory pService, String pComment ) {
        long tTimeDiff = 0;
        long tAbuseLogTime = 0;
        try {
            tAbuseLogTime = SDFTIME.parse( pTimeStr).getTime();
            tTimeDiff = System.currentTimeMillis() - SDFTIME.parse( pTimeStr).getTime();
        }
        catch( ParseException e) { e.printStackTrace();}

        if ((mAbuseIP != null) && (!isAllowedNode( pIpAddr))) {
            mAbuseIP.report( pIpAddr, pService, pComment, tAbuseLogTime );
        }

        if (tTimeDiff > mBlackListTime) {
            return;
        }

        BadIpAddr tEntry = mBadIpEntries.get( pIpAddr );
        if ((tEntry == null) && (!isAllowedNode( pIpAddr))) {
            tEntry = new BadIpAddr( pIpAddr, pTimeStr, true, pService.toString());
            mBadIpEntries.put( pIpAddr, tEntry );

        } else if (!isAllowedNode( pIpAddr)) {
            tEntry.updateTime( pTimeStr );
        }
    }




}
