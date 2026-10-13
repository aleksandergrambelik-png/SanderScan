import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SanderScan {

    static final String R   = "\u001B[0m";
    static final String B   = "\u001B[1m";
    static final String RED = "\u001B[31m";
    static final String GRN = "\u001B[32m";
    static final String YEL = "\u001B[33m";
    static final String MAG = "\u001B[35m";
    static final String CYA = "\u001B[36m";
    static final String GRY = "\u001B[90m";

    static final int TIMEOUT = 300;
    static final int THREADS = 250;

    static final Map<Integer,String> SVC = new LinkedHashMap<>();
    static {
        int[] p = {21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,515,
                   548,554,587,631,636,873,993,995,1080,1433,1521,1723,1883,1900,
                   2049,2375,3000,3306,3389,4443,5000,5060,5353,5432,5555,5900,
                   5985,6379,7000,8000,8008,8080,8081,8443,8888,9000,9090,9100,
                   9200,10000,11211,27017,50000,62078};
        String[] n = {"FTP","SSH","Telnet","SMTP","DNS","HTTP","POP3","rpcbind",
                      "MSRPC","NetBIOS","IMAP","SNMP","LDAP","HTTPS","SMB","SMTPS",
                      "LPD","AFP","RTSP","SMTP-sub","IPP","LDAPS","rsync","IMAPS",
                      "POP3S","SOCKS","MSSQL","Oracle","PPTP","MQTT","SSDP","NFS",
                      "Docker","Grafana/Node","MySQL","RDP","HTTPS-alt","UPnP","SIP",
                      "mDNS","PostgreSQL","ADB","VNC","WinRM","Redis","AirPlay",
                      "HTTP-alt","HTTP-alt","HTTP-proxy","HTTP-alt","HTTPS-alt",
                      "HTTP-alt","HTTP-alt","Cockpit","Printer","Elasticsearch",
                      "Webmin","Memcached","MongoDB","SAP","iPhone-Sync"};
        for (int i = 0; i < p.length; i++) SVC.put(p[i], n[i]);
    }

    static final int[] TOP_PORTS;
    static {
        TOP_PORTS = SVC.keySet().stream().mapToInt(Integer::intValue).sorted().toArray();
    }

    static final int[] HTTP_PORTS = {80,81,88,591,3000,5000,7001,8000,8008,8080,
                                     8081,8088,8888,9000,9090,9200,10000};
    static final int[] DISCOVERY = {80,443,22,53,445,139,8080,8008,7000,62078,
                                    9100,23,21,3389,554,5000,5555,1883,3306};

    static final Map<String,String> OUI = new HashMap<>();
    static {
        String[][] v = {
            {"001A11","Google"},   {"3C5A37","Samsung"}, {"F4F5D8","Samsung"},
            {"001E58","D-Link"},   {"1CBDB9","D-Link"},  {"0022B0","D-Link"},
            {"F81A67","TP-Link"},  {"50C7BF","TP-Link"}, {"B0958E","TP-Link"},
            {"001DD3","Xiaomi"},   {"64B473","Xiaomi"},  {"F8A45F","Xiaomi"},
            {"286C07","Xiaomi"},   {"AC220B","Asus"},    {"2C56DC","Asus"},
            {"001C10","Cisco"},    {"C0C1C0","Cisco"},   {"0018F8","Cisco"},
            {"B827EB","Raspberry Pi"}, {"DCA632","Raspberry Pi"}, {"E45F01","Raspberry Pi"},
            {"001B63","Apple"},    {"F0DBF8","Apple"},   {"AC61EA","Apple"},
            {"3C0754","Apple"},    {"5866BA","Huawei"},  {"00259E","Huawei"},
            {"00E0FC","Huawei"},   {"001349","Zyxel"},   {"5CE28C","Zyxel"},
            {"9C3DCF","Netgear"},  {"204E7F","Netgear"}, {"A00460","Netgear"},
            {"001F33","Netgear"},  {"000C29","VMware"},  {"005056","VMware"},
            {"080027","VirtualBox"}, {"001636","Huawei"}, {"28C68E","Netgear"}
        };
        for (String[] a : v) OUI.put(a[0], a[1]);
    }

    public static void main(String[] args) {
        try {
            if (args.length > 0 && (args[0].equals("-h") || args[0].equals("--help"))) {
                usage(); return;
            }

            boolean useUDP = false;
            String target = null;
            String portSpec = null;

            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("--udp")) {
                    useUDP = true;
                } else if (target == null) {
                    target = args[i];
                } else if (portSpec == null) {
                    portSpec = args[i];
                }
            }

            int[] ports = portSpec != null ? parsePorts(portSpec) : TOP_PORTS;

            List<String> hosts;
            if (target == null) {
                String net = autoSubnet();
                if (net == null) {
                    System.out.println(RED + "✗ Cannot detect local network." + R);
                    return;
                }
                System.out.println(CYA + "i Network detected: " + B + net + R);
                hosts = cidr(net);
            } else {
                hosts = expand(target);
            }

            scan(hosts, ports, useUDP);

        } catch (Exception e) {
            System.out.println(RED + "Error: " + e + R);
        } finally {
            System.out.print(R);
        }
    }

    static void usage() {
        System.out.println(B + "SanderScan — LAN & Port Scanner" + R);
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java SanderScan                        # auto-detect network");
        System.out.println("  java SanderScan 192.168.1.5            # single host, top ports");
        System.out.println("  java SanderScan 192.168.1.0/24         # full subnet");
        System.out.println("  java SanderScan 192.168.1.1-50         # IP range");
        System.out.println("  java SanderScan 192.168.1.5 1-1024     # port range");
        System.out.println("  java SanderScan 192.168.1.5 22,80,443  # specific ports");
        System.out.println("  java SanderScan 192.168.1.1 --udp 53,161,67  # UDP scan");
    }

    static String autoSubnet() throws Exception {
        String wlan = null, other = null;
        Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
        while (en.hasMoreElements()) {
            NetworkInterface ni = en.nextElement();
            if (!ni.isUp() || ni.isLoopback()) continue;
            String name = ni.getName().toLowerCase();
            if (name.startsWith("rmnet") || name.startsWith("ccmni")
                    || name.startsWith("p2p") || name.contains("dummy")) continue;

            for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                InetAddress a = ia.getAddress();
                if (!(a instanceof Inet4Address)) continue;
                if (a.isLoopbackAddress() || a.isLinkLocalAddress()) continue;
                if (ia.getNetworkPrefixLength() >= 31) continue;

                String c = a.getHostAddress() + "/" + ia.getNetworkPrefixLength();
                if (name.startsWith("wlan")) wlan = c;
                else if (other == null && a.isSiteLocalAddress()) other = c;
            }
        }
        return wlan != null ? wlan : other;
    }

    static List<String> expand(String t) throws Exception {
        if (t.contains("/")) return cidr(t);
        Matcher m = Pattern.compile("^(\\d+\\.\\d+\\.\\d+\\.)(\\d+)-(\\d+)$").matcher(t);
        if (m.matches()) {
            int a = Integer.parseInt(m.group(2)), b = Integer.parseInt(m.group(3));
            List<String> l = new ArrayList<>();
            for (int i = a; i <= b; i++) l.add(m.group(1) + i);
            return l;
        }
        return new ArrayList<>(List.of(t));
    }

    static List<String> cidr(String spec) throws Exception {
        String[] sp = spec.split("/");
        long ip   = toLong(InetAddress.getByName(sp[0]).getAddress());
        int  pfx  = Integer.parseInt(sp[1]);
        long mask = pfx <= 0 ? 0L : (0xFFFFFFFFL << (32 - pfx)) & 0xFFFFFFFFL;
        long net  = ip & mask;

        long total = (0xFFFFFFFFL & ~mask) - 1;
        if (total < 1) total = 1;
        if (total > 1024) {
            System.out.println(YEL + "! Large subnet, limited to 1024 hosts" + R);
            total = 1024;
        }
        List<String> out = new ArrayList<>((int) total);
        for (long i = 1; i <= total; i++) out.add(toIp(net + i));
        return out;
    }

    static long toLong(byte[] b) {
        long v = 0;
        for (int i = 0; i < 4; i++) v = (v << 8) | (b[i] & 0xFF);
        return v;
    }

    static String toIp(long v) {
        return ((v >> 24) & 0xFF) + "." + ((v >> 16) & 0xFF) + "."
             + ((v >> 8) & 0xFF) + "." + (v & 0xFF);
    }

    static int[] parsePorts(String spec) {
        Set<Integer> set = new TreeSet<>();
        for (String part : spec.split(",")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            if (part.contains("-")) {
                String[] ab = part.split("-", 2);
                int a = Integer.parseInt(ab[0].trim()), b = Integer.parseInt(ab[1].trim());
                for (int i = a; i <= b && i <= 65535; i++) if (i > 0) set.add(i);
            } else {
                int v = Integer.parseInt(part);
                if (v > 0 && v <= 65535) set.add(v);
            }
        }
        if (set.isEmpty()) return TOP_PORTS;
        int[] r = new int[set.size()];
        int i = 0;
        for (int v : set) r[i++] = v;
        return r;
    }

    static void scan(List<String> hosts, int[] ports, boolean useUDP) throws Exception {
        long t0 = System.currentTimeMillis();

        System.out.println();
        System.out.println(B + "╔══════════════════════════════════════════╗" + R);
        System.out.println(B + "║     SanderScan · LAN & Port Scanner      ║" + R);
        System.out.println(B + "╚══════════════════════════════════════════╝" + R);
        System.out.println(GRY + " host : " + hosts.size() + "   port : " + ports.length + R);
        System.out.println();

        ExecutorService pool = Executors.newFixedThreadPool(THREADS);

        System.out.println(CYA + "► Fase 1/2  searching for active hosts…" + R);
        List<String> alive = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger cnt = new AtomicInteger();

        for (String h : hosts) {
            pool.submit(() -> {
                for (int p : DISCOVERY) {
                    boolean aliveHost = useUDP ? probeUDP(h, p, 200) : probe(h, p, 200);
                    if (aliveHost) { alive.add(h); break; }
                }
                cnt.incrementAndGet();
            });
        }
        pool.shutdown();
        pool.awaitTermination(60, TimeUnit.MINUTES);
        System.out.println();

        if (alive.isEmpty()) {
            System.out.println(YEL + "  No hosts responded." + R);
            System.out.println(GRY + "  Tip: make sure Wi-Fi is on & your device is on the same network." + R);
            return;
        }

        List<String> sorted = new ArrayList<>(alive);
        sorted.sort(Comparator.comparingLong(x -> ipKey(x)));
        System.out.println(GRN + "  ✓ " + sorted.size() + " active hosts found" + R);

        System.out.println();
        System.out.println(CYA + "► Fase 2/2  port scan…" + R);

        Map<String, List<Integer>> found = new ConcurrentHashMap<>();
        pool = Executors.newFixedThreadPool(THREADS);
        for (String h : sorted) {
            for (int p : ports) {
                pool.submit(() -> {
                    boolean isOpen = useUDP ? probeUDP(h, p, TIMEOUT) : probe(h, p, TIMEOUT);
                    if (isOpen) {
                        found.computeIfAbsent(h, k -> Collections.synchronizedList(new ArrayList<>()))
                             .add(p);
                    }
                });
            }
        }
        pool.shutdown();
        pool.awaitTermination(60, TimeUnit.MINUTES);

        Map<String,String> arp = readArp();
        int totalOpen = 0;

        System.out.println();

        for (String h : sorted) {
            List<Integer> list = found.get(h);
            if (list == null || list.isEmpty()) continue;
            Collections.sort(list);
            totalOpen += list.size();

            String mac    = arp.get(h);
            String vendor = vendorOf(mac);
            String os = detectOS(h);
            if (os.equals("Unknown")) os = guessOSByVendor(vendor);

            StringBuilder head = new StringBuilder();
            head.append(B).append(MAG).append("┌─ ").append(h).append(R);
            if (mac != null)    head.append(GRY).append("  ").append(mac).append(R);
            if (vendor != null) head.append(CYA).append("  [").append(vendor).append("]").append(R);
            head.append(GRN).append("  OS: ").append(os).append(R);
            System.out.println(head);

            for (int p : list) {
                String svc = SVC.getOrDefault(p, "unknown");
                String ban = "";
                try { ban = banner(h, p); } catch (Exception ignored) {}
                if (ban == null) ban = "";

                System.out.println("│  " + B + p + "/tcp" + R
                        + "  " + GRN + "open" + R
                        + "  " + pad(svc, 14)
                        + " " + GRY + ban + R);
            }
            System.out.println(MAG + "└─" + R);
        }

        if (totalOpen == 0) {
            System.out.println(YEL + "  No open ports found." + R);
        }

        System.out.println();
        System.out.println(B + GRN + "✓ Done" + R + GRY + " — "
                + ((System.currentTimeMillis() - t0) / 1000.0) + "s, "
                + totalOpen + " open ports" + R);

        if (!found.isEmpty()) {
            System.out.println(CYA + "► Exporting results..." + R);
            exportCSV(found, arp);
            exportJSON(found, arp);
        }
    }

    static long ipKey(String ip) {
        try { return toLong(InetAddress.getByName(ip).getAddress()); }
        catch (Exception e) { return 0; }
    }

    static String pad(String s, int n) {
        if (s == null) s = "";
        return s.length() >= n ? s : s + " ".repeat(n - s.length());
    }

    static boolean probe(String host, int port, int timeout) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeout);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean probeUDP(String host, int port, int timeout) {
        try (DatagramSocket ds = new DatagramSocket()) {
            ds.setSoTimeout(timeout);
            byte[] buf = new byte[1];
            DatagramPacket dp = new DatagramPacket(buf, buf.length,
                    InetAddress.getByName(host), port);
            ds.send(dp);
            byte[] recv = new byte[1024];
            DatagramPacket resp = new DatagramPacket(recv, recv.length);
            ds.receive(resp);
            return true;
        } catch (SocketTimeoutException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    static String banner(String host, int port) {
        if (port == 443 || port == 8443 || port == 4443) return "";
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 800);
            s.setSoTimeout(700);

            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            for (int hp : HTTP_PORTS) {
                if (hp == port) {
                    out.write(("HEAD / HTTP/1.0\r\nHost: " + host
                             + "\r\nUser-Agent: SanderScan\r\n\r\n").getBytes());
                    out.flush();
                    break;
                }
            }

            byte[] buf = new byte[256];
            int n;
            try {
                n = in.read(buf);
            } catch (SocketTimeoutException e) {
                return "";
            }
            if (n <= 0) return "";

            String s1 = new String(buf, 0, n).replaceAll("\\s+", " ").trim();
            if (s1.length() > 70) s1 = s1.substring(0, 70) + "…";
            return s1;
        } catch (Exception e) {
            return "";
        }
    }

    static void exportCSV(Map<String, List<Integer>> found, Map<String, String> arp) {
        try (FileWriter fw = new FileWriter("scan_result.csv")) {
            fw.write("IP,MAC,Vendor,Port,Service\n");
            for (Map.Entry<String, List<Integer>> entry : found.entrySet()) {
                String ip = entry.getKey();
                String mac = arp.get(ip);
                String vendor = vendorOf(mac);
                List<Integer> ports = entry.getValue();
                Collections.sort(ports);
                for (int p : ports) {
                    String svc = SVC.getOrDefault(p, "unknown");
                    fw.write(ip + ","
                            + (mac != null ? mac : "") + ","
                            + (vendor != null ? vendor : "") + ","
                            + p + ","
                            + svc + "\n");
                }
            }
            System.out.println(GRN + "✓ Results saved to scan_result.csv" + R);
        } catch (IOException e) {
            System.out.println(RED + "✗ Failed to export CSV: " + e.getMessage() + R);
        }
    }

    static void exportJSON(Map<String, List<Integer>> found, Map<String, String> arp) {
        try (FileWriter fw = new FileWriter("scan_result.json")) {
            fw.write("{\n");
            int hostCount = 0;
            for (Map.Entry<String, List<Integer>> entry : found.entrySet()) {
                String ip = entry.getKey();
                String mac = arp.get(ip);
                String vendor = vendorOf(mac);
                List<Integer> ports = entry.getValue();
                Collections.sort(ports);

                fw.write("  \"" + ip + "\": {\n");
                fw.write("    \"mac\": \"" + (mac != null ? mac : "") + "\",\n");
                fw.write("    \"vendor\": \"" + (vendor != null ? vendor : "") + "\",\n");
                fw.write("    \"ports\": [\n");
                for (int i = 0; i < ports.size(); i++) {
                    int p = ports.get(i);
                    String svc = SVC.getOrDefault(p, "unknown");
                    fw.write("      {\"port\": " + p + ", \"service\": \"" + svc + "\"}");
                    if (i < ports.size() - 1) fw.write(",");
                    fw.write("\n");
                }
                fw.write("    ]\n");
                fw.write("  }");
                hostCount++;
                if (hostCount < found.size()) fw.write(",");
                fw.write("\n");
            }
            fw.write("}\n");
            System.out.println(GRN + "✓ Results saved to scan_result.json" + R);
        } catch (IOException e) {
            System.out.println(RED + "✗ Failed to export JSON: " + e.getMessage() + R);
        }
    }

    static String detectOS(String host) {
        try {
            Process p = Runtime.getRuntime().exec("ping -c 1 -W 1 " + host);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            int ttl = -1;
            while ((line = br.readLine()) != null) {
                Matcher m = Pattern.compile("ttl=(\\d+)", Pattern.CASE_INSENSITIVE).matcher(line);
                if (m.find()) {
                    ttl = Integer.parseInt(m.group(1));
                    break;
                }
            }
            br.close();
            if (ttl == -1) return "Unknown";
            if (ttl <= 64) return "Linux/Android/Unix";
            if (ttl <= 128) return "Windows";
            if (ttl <= 255) return "Cisco/Network Device";
            return "Unknown";
        } catch (Exception e) {
            return "Unknown";
        }
    }

    static String guessOSByVendor(String vendor) {
        if (vendor == null) return "Unknown";
        vendor = vendor.toLowerCase();
        if (vendor.contains("xiaomi") || vendor.contains("samsung")
                || vendor.contains("huawei") || vendor.contains("oppo")
                || vendor.contains("vivo") || vendor.contains("realme")) {
            return "Android";
        }
        if (vendor.contains("apple")) return "iOS/macOS";
        if (vendor.contains("cisco") || vendor.contains("tp-link")
                || vendor.contains("netgear") || vendor.contains("d-link")
                || vendor.contains("zyxel") || vendor.contains("huawei")) {
            return "Router (Linux)";
        }
        if (vendor.contains("vmware") || vendor.contains("virtualbox")) {
            return "Virtual Machine";
        }
        if (vendor.contains("raspberry")) return "Linux (RPi)";
        return "Unknown";
    }

    static Map<String,String> readArp() {
        Map<String,String> m = new HashMap<>();
        Path p = Paths.get("/proc/net/arp");
        if (!Files.isReadable(p)) return m;
        try (BufferedReader br = Files.newBufferedReader(p)) {
            br.readLine();
            String line;
            while ((line = br.readLine()) != null) {
                String[] t = line.trim().split("\\s+");
                if (t.length >= 4
                        && t[3].matches("([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
                        && !t[3].equals("00:00:00:00:00:00")) {
                    m.put(t[0], t[3].toLowerCase());
                }
            }
        } catch (Exception ignored) {}
        return m;
    }

    static String vendorOf(String mac) {
        if (mac == null) return null;
        String hex = mac.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        if (hex.length() < 6) return null;
        return OUI.get(hex.substring(0, 6));
    }
}
