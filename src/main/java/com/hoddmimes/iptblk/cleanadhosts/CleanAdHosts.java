package com.hoddmimes.iptblk.cleanadhosts;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CleanAdHosts
{
    public static String cAdHostsInFile = "adservers.txt";
    public static String cpAdHostsOutFile = "adservers-ipaddr.txt";
    public static String cFwGroup = "BACKLIST_OUT";
    public static Pattern cAddrPattern = Pattern.compile("^0\\.0\\.0\\.0 (.*)");

    HashMap<String,String> mAddrMap = new HashMap<>();


    public static void main( String[] args  ) {
        CleanAdHosts p = new CleanAdHosts();
        p.hostsToAddresses(cAdHostsInFile);
        p.presentAddresses();
    }

    private String hostnameToIpAddress( String pHostName ) {
        try {
            InetAddress tAddress = InetAddress.getByName(pHostName);
            return tAddress.getHostAddress();
        }
        catch( UnknownHostException e) {
            System.out.println("Unknown host address for \"" + pHostName + "\"");
            return null;
        }
    }

    private void presentAddresses() {
        PrintWriter fp = null;
        try
        {
           fp = new PrintWriter(cpAdHostsOutFile, "UTF-8");
            for( String tAddr : mAddrMap.values()) {
                fp.println("-A " + cFwGroup + " " + tAddr );
            }
            fp.flush();
            fp.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }





    private void hostsToAddresses( String pAdServersFile) {
        Pattern tAddrPattern = Pattern.compile("^0\\.0\\.0\\.0 (.*)");

        try {
            Scanner scanner = new Scanner(new File(pAdServersFile));
            while (scanner.hasNextLine()) {
                String tLine = scanner.nextLine();
                Matcher m = cAddrPattern.matcher(tLine);
                if (m.find()) {
                    String tHostName = m.group(1);
                    String tIpAddr = hostnameToIpAddress(tHostName);
                    if (tIpAddr != null) {
                        mAddrMap.put(tIpAddr,tIpAddr);
                    }
                }
            }
            scanner.close();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
    }
}
