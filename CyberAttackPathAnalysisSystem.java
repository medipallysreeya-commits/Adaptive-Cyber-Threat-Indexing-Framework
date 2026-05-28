import java.util.*;

public class CyberAttackPathAnalysisSystem {

    static class Edge {

        int destination;
        int weight;

        Edge(int destination, int weight) {

            this.destination = destination;
            this.weight = weight;
        }
    }

    static void bfs(ArrayList<Edge>[] graph,
                    int start,
                    boolean[] visited) {

        Queue<Integer> queue = new LinkedList<>();

        queue.add(start);

        visited[start] = true;

        System.out.print("\nBFS Traversal : ");

        while (!queue.isEmpty()) {

            int current = queue.poll();

            System.out.print(current + " ");

            for (Edge e : graph[current]) {

                if (!visited[e.destination]) {

                    visited[e.destination] = true;

                    queue.add(e.destination);
                }
            }
        }

        System.out.println();
    }

    static void dfs(ArrayList<Edge>[] graph,
                    int current,
                    boolean[] visited) {

        visited[current] = true;

        System.out.print(current + " ");

        for (Edge e : graph[current]) {

            if (!visited[e.destination]) {

                dfs(graph,
                    e.destination,
                    visited);
            }
        }
    }

    static void dijkstra(ArrayList<Edge>[] graph,
                         int source) {

        int vertices = graph.length;

        int[] distance = new int[vertices];

        Arrays.fill(distance, Integer.MAX_VALUE);

        distance[source] = 0;

        PriorityQueue<int[]> pq =
            new PriorityQueue<>(
                Comparator.comparingInt(a -> a[1]));

        pq.add(new int[]{source, 0});

        while (!pq.isEmpty()) {

            int[] current = pq.poll();

            int node = current[0];

            int dist = current[1];

            for (Edge e : graph[node]) {

                int newDistance =
                    dist + e.weight;

                if (newDistance <
                    distance[e.destination]) {

                    distance[e.destination] =
                        newDistance;

                    pq.add(new int[] {
                        e.destination,
                        newDistance
                    });
                }
            }
        }

        System.out.println("\nShortest Attack Paths:");

        for (int i = 0; i < vertices; i++) {

            System.out.println("Node "
                               + source
                               + " -> Node "
                               + i
                               + " : "
                               + distance[i]);
        }
    }

    public static void main(String[] args) {

        int vertices = 6;

        ArrayList<Edge>[] graph =
            new ArrayList[vertices];

        for (int i = 0; i < vertices; i++) {

            graph[i] = new ArrayList<>();
        }

        // Network Connections

        graph[0].add(new Edge(1, 4));
        graph[0].add(new Edge(2, 2));

        graph[1].add(new Edge(3, 5));

        graph[2].add(new Edge(3, 1));
        graph[2].add(new Edge(4, 7));

        graph[3].add(new Edge(5, 3));

        graph[4].add(new Edge(5, 2));

        System.out.println("====================================");
        System.out.println(" CYBER ATTACK PATH ANALYSIS SYSTEM ");
        System.out.println("====================================");

        System.out.println("\nCompromised Network Nodes:");
        System.out.println("0 -> Main Server");
        System.out.println("1 -> Firewall");
        System.out.println("2 -> Authentication Server");
        System.out.println("3 -> Internal Network");
        System.out.println("4 -> Backup Server");
        System.out.println("5 -> Database Server");

        boolean[] visitedBFS =
            new boolean[vertices];

        bfs(graph,
            0,
            visitedBFS);

        boolean[] visitedDFS =
            new boolean[vertices];

        System.out.print("\nDFS Traversal : ");

        dfs(graph,
            0,
            visitedDFS);

        System.out.println();

        dijkstra(graph,
                 0);

        System.out.println("\n====================================");
        System.out.println(" Potential Attack Route Identified ");
        System.out.println(" Immediate Network Isolation Recommended ");
        System.out.println("====================================");
    }
}