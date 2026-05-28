import java.util.*;

class SegmentTree {

    int[] tree;
    int n;

    SegmentTree(int[] traffic) {

        n = traffic.length;

        tree = new int[4 * n];

        build(traffic, 1, 0, n - 1);
    }

    void build(int[] traffic,
               int node,
               int start,
               int end) {

        if (start == end) {

            tree[node] = traffic[start];
        }

        else {

            int mid = (start + end) / 2;

            build(traffic,
                  2 * node,
                  start,
                  mid);

            build(traffic,
                  2 * node + 1,
                  mid + 1,
                  end);

            tree[node] =
                tree[2 * node] +
                tree[2 * node + 1];
        }
    }

    int query(int node,
              int start,
              int end,
              int left,
              int right) {

        if (right < start || end < left)
            return 0;

        if (left <= start && end <= right)
            return tree[node];

        int mid = (start + end) / 2;

        return query(2 * node,
                     start,
                     mid,
                     left,
                     right)

             + query(2 * node + 1,
                     mid + 1,
                     end,
                     left,
                     right);
    }
}

public class NetworkTrafficSpikeDetectionSystem {

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        int[] traffic = {

            500,
            700,
            650,
            12000,
            15000,
            14000,
            800,
            750
        };

        SegmentTree st =
            new SegmentTree(traffic);

        System.out.println("====================================");
        System.out.println(" NETWORK TRAFFIC ANALYSIS SYSTEM ");
        System.out.println("====================================");

        System.out.println("\nHourly Traffic Records:");
        System.out.println("Hour 1 : 500 packets");
        System.out.println("Hour 2 : 700 packets");
        System.out.println("Hour 3 : 650 packets");
        System.out.println("Hour 4 : 12000 packets");
        System.out.println("Hour 5 : 15000 packets");
        System.out.println("Hour 6 : 14000 packets");
        System.out.println("Hour 7 : 800 packets");
        System.out.println("Hour 8 : 750 packets");

        System.out.println("\n====================================");

        int totalTraffic =
            st.query(1,
                     0,
                     traffic.length - 1,
                     3,
                     5);

        System.out.println("Traffic Analysis Interval : Hour 4 to Hour 6");

        System.out.println("Total Packets Detected : "
                           + totalTraffic);

        if (totalTraffic > 30000) {

            System.out.println("\n!!! TRAFFIC SPIKE DETECTED !!!");
            System.out.println("Possible DDoS Attack Identified");
            System.out.println("Immediate Firewall Monitoring Required");
        }

        else {

            System.out.println("\nTraffic Status : NORMAL");
        }

        System.out.println("====================================");

        sc.close();
    }
}