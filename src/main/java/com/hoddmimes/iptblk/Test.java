package com.hoddmimes.iptblk;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Test {



    private void test() {
        ArrayList<String> tLogMsgs = new ArrayList<>();
        tLogMsgs.add("2020-08-26 06:00:48 hoddmimes sshd[8327]: Invalid user edp from 182.56.29.87 port 40580");
        tLogMsgs.add("2020-08-25 18:43:03 hoddmimes auth[32422]: pam_unix(dovecot:auth): authentication failure; logname= uid=0 euid=0 tty=dovecot ruser=lena.bertilsson@hoddmimes.com rhost=184.178.172.7");


        ArrayList<Pattern> tPatterns = new ArrayList<>();
        tPatterns.add(Pattern.compile("^(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) .* Invalid user .* from (\\d+\\.\\d+\\.\\d+\\.\\d+) port \\d+"));
        tPatterns.add(Pattern.compile("^(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) .* invalid user .* (\\d+\\.\\d+\\.\\d+\\.\\d+) port \\d+ \\[preauth\\]"));
        tPatterns.add(Pattern.compile("^(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+) .* pam_unix\\(dovecot:auth\\): authentication failure; .* rhost=(\\d+\\.\\d+\\.\\d+\\.\\d+)"));

        for( int t = 0; t < tLogMsgs.size(); t++) {
            for( int p = 0; p < tPatterns.size(); p++ ) {
                Matcher m = tPatterns.get(p).matcher( tLogMsgs.get(t) );
                if (m.matches()) {
                    System.out.println("[MATCH] Text: " + t + " Pattern: " + p );
                }
            }
        }
    }
    public static void main( String[] args ) {
        Test t = new Test();
        t.test();
    }
}
