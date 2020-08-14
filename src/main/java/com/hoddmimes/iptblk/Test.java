package com.hoddmimes.iptblk;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Test {

    private void test() {
        String tLine = "[2020-08-13 22:08:15.384580] [error] [pid 3492] mod_cgid.c(1077): [client 89.158.77.24:3920] AH01264: script not found or unable to stat: /var/www/cgi-bin/kerbynet";
        Pattern tErrorPattern1 = Pattern.compile("^\\[(\\d+-\\d+-\\d+ \\d+:\\d+:\\d+)\\.\\d+\\] \\[error\\] .+ \\[client (\\d+\\.\\d+\\.\\d+\\.\\d+):\\d+\\] .+ script not found or unable to stat.*");
        Matcher m = tErrorPattern1.matcher( tLine );
        if (m.matches()) {
            System.out.println("Match groups: " + m.groupCount());
        } else {
            System.out.println("No match");
        }


    }
    public static void main( String[] args ) {
        Test t = new Test();
        t.test();
    }
}
