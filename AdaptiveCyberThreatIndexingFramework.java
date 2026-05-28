import java.util.*;

class Node {

    int ip, height, count, riskScore;
    String threat, severity, status;

    Node left, right;

    Node(int ip, String threat, String severity) {

        this.ip = ip;
        this.threat = threat;
        this.severity = severity;

        this.count = 1;
        this.height = 1;

        if (severity.equalsIgnoreCase("Critical")) {
            this.riskScore = 100;
            this.status = "BLOCKED";
        }

        else if (severity.equalsIgnoreCase("Medium")) {
            this.riskScore = 50;
            this.status = "MONITORED";
        }

        else {
            this.riskScore = 20;
            this.status = "SAFE";
        }
    }
}

public class AdaptiveCyberThreatIndexingFramework {

    Node root;

    int height(Node n) {

        if (n == null)
            return 0;

        return n.height;
    }

    int getBalance(Node n) {

        if (n == null)
            return 0;

        return height(n.left) - height(n.right);
    }

    Node rightRotate(Node y) {

        Node x = y.left;
        Node t2 = x.right;

        x.right = y;
        y.left = t2;

        y.height = Math.max(height(y.left),
                            height(y.right)) + 1;

        x.height = Math.max(height(x.left),
                            height(x.right)) + 1;

        return x;
    }

    Node leftRotate(Node x) {

        Node y = x.right;
        Node t2 = y.left;

        y.left = x;
        x.right = t2;

        x.height = Math.max(height(x.left),
                            height(x.right)) + 1;

        y.height = Math.max(height(y.left),
                            height(y.right)) + 1;

        return y;
    }

    Node insert(Node node,
                int ip,
                String threat,
                String severity) {

        if (node == null)
            return new Node(ip, threat, severity);

        if (ip < node.ip)
            node.left = insert(node.left,
                               ip,
                               threat,
                               severity);

        else if (ip > node.ip)
            node.right = insert(node.right,
                                ip,
                                threat,
                                severity);

        else {

            node.count++;

            if (node.severity.equalsIgnoreCase("Critical"))
                node.riskScore = node.count * 100;

            else if (node.severity.equalsIgnoreCase("Medium"))
                node.riskScore = node.count * 50;

            else
                node.riskScore = node.count * 20;

            return node;
        }

        node.height = 1 + Math.max(height(node.left),
                                   height(node.right));

        int balance = getBalance(node);

        // LL Rotation
        if (balance > 1 && ip < node.left.ip)
            return rightRotate(node);

        // RR Rotation
        if (balance < -1 && ip > node.right.ip)
            return leftRotate(node);

        // LR Rotation
        if (balance > 1 && ip > node.left.ip) {

            node.left = leftRotate(node.left);

            return rightRotate(node);
        }

        // RL Rotation
        if (balance < -1 && ip < node.right.ip) {

            node.right = rightRotate(node.right);

            return leftRotate(node);
        }

        return node;
    }

    void search(Node node, int ip) {

        if (node == null) {

            System.out.println("\n=================================");
            System.out.println(" Threat Status : SAFE ");
            System.out.println(" No Threat Record Found ");
            System.out.println("=================================");

            return;
        }

        if (ip == node.ip) {

            System.out.println("\n=================================");
            System.out.println("     THREAT ANALYSIS REPORT");
            System.out.println("=================================");

            System.out.println("IP Address   : " + node.ip);
            System.out.println("Threat Type  : " + node.threat);
            System.out.println("Severity     : " + node.severity);
            System.out.println("Attack Count : " + node.count);
            System.out.println("Risk Score   : " + node.riskScore);
            System.out.println("Status       : " + node.status);
            if (node.status.equals("BLOCKED")) {

    System.out.println("\n!!! CRITICAL THREAT BLOCKED !!!");
    System.out.println("Immediate Security Action Recommended");
}

            System.out.println("=================================");

            return;
        }

        if (ip < node.ip)
            search(node.left, ip);

        else
            search(node.right, ip);
    }

    void inorder(Node node) {

        if (node != null) {

            inorder(node.left);

            System.out.println("\n---------------------------------");
            System.out.println("IP Address   : " + node.ip);
            System.out.println("Threat Type  : " + node.threat);
            System.out.println("Severity     : " + node.severity);
            System.out.println("Attack Count : " + node.count);
            System.out.println("Risk Score   : " + node.riskScore);
            System.out.println("Status       : " + node.status);
            System.out.println("---------------------------------");

            inorder(node.right);
        }
    }

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        AdaptiveCyberThreatIndexingFramework obj =
            new AdaptiveCyberThreatIndexingFramework();

        // Preloaded Threat Records

        obj.root = obj.insert(obj.root,
                              192168110,
                              "Malware",
                              "Critical");

        obj.root = obj.insert(obj.root,
                              192168125,
                              "DDoS",
                              "Medium");

        obj.root = obj.insert(obj.root,
                              172160001,
                              "Phishing",
                              "Low");

        obj.root = obj.insert(obj.root,
                              101010101,
                              "Ransomware",
                              "Critical");

        obj.root = obj.insert(obj.root,
                              192168110,
                              "Malware",
                              "Critical");

        obj.root = obj.insert(obj.root,
                              909090909,
                              "Spyware",
                              "Medium");

        int choice;

        System.out.println("====================================");
        System.out.println(" ADAPTIVE CYBER THREAT FRAMEWORK ");
        System.out.println("====================================");

        do {

            System.out.println("\n=========== MENU ===========");
            System.out.println("1. Log Suspicious Activity");
            System.out.println("2. Search Threat");
            System.out.println("3. Display Threat Database");
            System.out.println("4. Exit");
            System.out.println("============================");

            System.out.print("Enter Choice : ");

            choice = sc.nextInt();

            switch (choice) {

                case 1:

                    System.out.print("\nEnter Suspicious IP Address : ");
                    int ip = sc.nextInt();

                    sc.nextLine();

                    System.out.print("Enter Threat Type : ");
                    String threat = sc.nextLine();

                    System.out.print("Enter Severity (Low/Medium/Critical) : ");
                    String severity = sc.nextLine();

                    obj.root = obj.insert(obj.root,
                                          ip,
                                          threat,
                                          severity);

                    System.out.println("\n---------------------------------");
                    System.out.println(" Threat Activity Logged Successfully ");
                    System.out.println("---------------------------------");
                    break;

                case 2:

                    System.out.print("\nEnter Suspicious IP Address : ");
                    int searchIP = sc.nextInt();

                    obj.search(obj.root, searchIP);

                    break;

                case 3:

                    System.out.println("\n=================================");
                    System.out.println(" CYBER THREAT DATABASE RECORDS ");
                    System.out.println("=================================");

                    obj.inorder(obj.root);

                    break;

                case 4:

                    System.out.println("\n=================================");
                    System.out.println(" System Shutdown Successful ");
                    System.out.println("=================================");

                    break;

                default:

                    System.out.println("\nInvalid Choice");
            }

        } while (choice != 4);

        sc.close();
    }
}