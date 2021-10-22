package analysis.urlAnalysis;

import analysis.urlAnalysis.specific.ApacheClientManager;
import analysis.urlAnalysis.specific.JavaNetManager;
import analysis.urlAnalysis.specific.OkHttpManager;
import analysis.urlAnalysis.specific.VolleyManager;
import configs.AppInfoConfig;
import models.ThirdPartyType;
import models.VulnResults;
import models.track.TrackModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.toolkits.callgraph.CallGraph;
import utils.SessDroidLogger;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ObtainUrlAnalysis {
    private Set<String> urls;
    private AppInfoConfig info;
    private CallGraph mCallgraph;
    private Logger mLogger;
    private boolean isSecAnti;
    private boolean isPicassoAsDownLoader;

    private static String CONTAIN_LETTER_REGEX = ".*[a-zA-z].*";

    public ObtainUrlAnalysis(AppInfoConfig appInfo, CallGraph callGraph) {
        this.urls = new HashSet<>();
        this.info = appInfo;
        this.mCallgraph = callGraph;
        this.mLogger = LoggerFactory.getLogger("urlAnalysis");
        this.isSecAnti = false;
        this.isPicassoAsDownLoader = false;
    }


    public void checkSendUrls(SootMethod sm, Unit u, Value value, ThirdPartyType type){
        Set<TrackModel> set = doTrackCallUrls(new TrackModel(sm, u, value), type);

        for (TrackModel urlPair : set){
            LoadUrlAnalysis urlAnalysis = new LoadUrlAnalysis(info, mCallgraph);
            String url = urlAnalysis.getLoadUrlStrings(urlPair);

            if (!url.contains("RESULT") && !url.isEmpty()){
                /*String[] orUrls = url.split("\\|");
                urls.addAll(Arrays.asList(orUrls));*/
                urls.add(url);
            }
            // 另外对于从callback方法获取得到的字符串，需要加入反模式
            if (urlAnalysis.isGetFromCallbacks()){
                isSecAnti = true;
            }

        }
    }

    /**
     * invoke after collect
     */
    public void dealCollectedUrls(){

        if (urls.isEmpty()){
            System.out.println("no explicit urls found in " + info.getApkName());
        }

        if (isPicassoAsDownLoader){
            isSecAnti = true;
        }
        for (String url : urls){
            if (!url.matches(CONTAIN_LETTER_REGEX)){
                continue;
            }
            if (!isLocalUrl(url)){
                isSecAnti = true;
            }
        }

        if (isSecAnti){
            if (isPicassoAsDownLoader){
                SessDroidLogger.Info("Find Send-out Token Defect (Interceptor with authToken set as DownLoader). " + info.getApkName());
            }
            else
                SessDroidLogger.Info("Find Send-out Token Defect. " + info.getApkName());

            VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.SEND_TO_EXTERNAL_DOMAIN_TOKEN, info.getApkName());
        }
    }


    /** TODO 有咩有可能一个sootmethod有多个valueunitpair？
     * main method
     * 1. getAllRequestsWithAuth()
     * 2. 对String类型的url参数进行track判断：1）直接是constant 2)local
     */
    /*public void doSecondAnalysis(SootMethod sm, Unit u, Value value, MainAnalysis.ThirdPartyType type){
        boolean isAnti = false;

        Set<TrackModel> set = doTrackCallUrls(new TrackModel(value, u, sm), type);
        //dealWithUrlParams(set);
        for (TrackModel urlPair : set){
            LoadUrlAnalysis urlAnalysis = new LoadUrlAnalysis(info);
            urls.add(urlAnalysis.getLoadUrlStrings(urlPair));
            if (urlAnalysis.isGetFromCallbacks()){
                isAnti = true;
            }
        }

        if (urls.isEmpty()){
            mLogger.info("There is no url in {} type!", type);
            return;
        }


        for (String url : urls){
            if (!isLocalUrl(url)){
                System.out.println("Send out token to external : " + url);
                isAnti = true;
            }
            else {
                System.out.println("Valid url : " + url);
            }
            if (!config.isFullAnalysis()){
                break;
            }
        }

        if (isAnti){
            mLogger.info("Find Send-out Token Bug. {}", info.getApkName());
            VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.SEND_TO_EXTERNAL_DOMAIN_TOKEN, info.getApkName());
        }
    }*/

    private Set<TrackModel> doTrackCallUrls(TrackModel input, ThirdPartyType type){
        Set<TrackModel> urlSet = new HashSet<>();

        switch (type) {
            case VOLLEY_TYPE:
                VolleyManager volleyManager = new VolleyManager(mCallgraph, info, input.getLocateMethod().getDeclaringClass());
                urlSet.addAll(volleyManager.getVolleyClientUrls());
                break;
            case OKHTTP_TYPE:
                OkHttpManager okHttpManager = new OkHttpManager(info, mCallgraph);
                urlSet.addAll(okHttpManager.getOkhttpClientUrls(input.getLocateMethod(), input.getLocateUnit(), input.getTargetValue()));
                if (okHttpManager.isPicassoDLoader){
                    isPicassoAsDownLoader = true;
                }
                break;
            case JAVA_NET_CONNECTION:
                JavaNetManager netManager = new JavaNetManager(info, mCallgraph);
                urlSet.addAll(netManager.getJavaNetUrls(input.getLocateMethod(), input.getLocateUnit(), input.getTargetValue()));
                break;
            case LOOPJ_SYNC:
                ApacheClientManager clientManager = new ApacheClientManager();
                clientManager.getApacheClientUrls(input);
        }

        return urlSet;

    }


    public Set<String> getUrls(){
        return this.urls;
    }


    //TODO to complete
    private boolean isLocalUrl(String urlStr){
        String packageName = info.getAppPackName();
        String[] strs = packageName.split("\\.");
        for (int i = 1; i < strs.length; i++){
            if (urlStr.contains(strs[i]) && !strs[i].equals("android")){
                return true;
            }
        }
        return false;
    }

    public boolean isAnti() {
        return isSecAnti;
    }
}
