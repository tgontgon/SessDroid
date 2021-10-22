package models;

import java.util.EnumMap;
import java.util.HashSet;
import java.util.Set;

public class VulnResults {
    private static VulnResults instance;

    private VulnResults(){}
    public static VulnResults getInstance(){
        if (instance == null){
            instance = new VulnResults();
        }
        return instance;
    }

    public enum Vulns {
        CLIENT_GENERATED_TOKEN("Client-generated token",1),
        PLAIN_SAVE_TOKEN("Token save in plain text", 2),
        LEAK_THROUGH_LOG("Token leaks to LOG",3),
        SEND_TO_EXTERNAL_DOMAIN_TOKEN("Token leaks to external domains",4),
        IMPROPER_EXPIRED_TOKEN("Improper-expired token",5);


        private final String name;
        private final int index;
        Vulns(final String name, final int index){
            this.name = name;
            this.index = index;
        }
        @Override
        public String toString() {
            return index + "-" + name + " : ";
        }
    }

    // 每一个vuln 对应一组满足该模式的apknames
    private EnumMap<Vulns, Set<String>> vulApps = new EnumMap<>(Vulns.class);


    /**
     * 增加vul数据
     * @param vulType
     * @param str app名称
     */
    public void addVulnPiece(Vulns vulType, String str){
        Set<String> vulSet = vulApps.getOrDefault(vulType, new HashSet<>());
        vulSet.add(str);
        vulApps.put(vulType, vulSet);
    }

    public Set<String> getFirstVulApps(){
        return vulApps.getOrDefault(Vulns.CLIENT_GENERATED_TOKEN, new HashSet<>());
    }
    public Set<String> getSecVulApps(){
        return vulApps.getOrDefault(Vulns.SEND_TO_EXTERNAL_DOMAIN_TOKEN, new HashSet<>());
    }
    public Set<String> getThirdVulApps(){
        return vulApps.getOrDefault(Vulns.LEAK_THROUGH_LOG, new HashSet<>());
    }
    public Set<String> getForthVulApps(){
        return vulApps.getOrDefault(Vulns.PLAIN_SAVE_TOKEN, new HashSet<>());
    }
    public Set<String> getFifthVulApps() {
        return vulApps.getOrDefault(Vulns.IMPROPER_EXPIRED_TOKEN, new HashSet<>());
    }


    public void printFirst(){
        Set<String> res = vulApps.getOrDefault(Vulns.CLIENT_GENERATED_TOKEN, new HashSet<>());
        System.out.println("count 1 : " + res.size());
        for (String str : res){
            System.out.println("-----" + str);
        }
    }
    public void printSec(){
        Set<String> res = vulApps.getOrDefault(Vulns.SEND_TO_EXTERNAL_DOMAIN_TOKEN, new HashSet<>());
        System.out.println("count 4 : " + res.size());
        for (String str : res){
            System.out.println("-----" + str);
        }
    }
    public void printThir(){
        Set<String> res = vulApps.getOrDefault(Vulns.LEAK_THROUGH_LOG, new HashSet<>());
        System.out.println("count 3 : " + res.size());
        for (String str : res){
            System.out.println("-----" + str);
        }
    }
    public void printFourth(){
        Set<String> res = vulApps.getOrDefault(Vulns.PLAIN_SAVE_TOKEN, new HashSet<>());
        System.out.println("count 2 : " + res.size());
        for (String str : res){
            System.out.println("-----" + str);
        }
    }
    public void printFifth() {
        Set<String> res = vulApps.getOrDefault(Vulns.IMPROPER_EXPIRED_TOKEN, new HashSet<>());
        System.out.println("count 5 : " + res.size());
        for (String str : res){
            System.out.println("-----" + str);
        }
    }

    public void printAll(){
        printFirst();
        printSec();
        printThir();
        printFourth();
        printFifth();
    }
}
