import analysis.defTrack.BackwardsTrackAnalysis;
import analysis.expire.ExpireAnalysis;
import analysis.pointsTo.CustomTaintAnalysis;
import analysis.pointsTo.LogAnalysis;
import analysis.save.PlainSaveAnalysis;
import analysis.urlAnalysis.ObtainUrlAnalysis;
import configs.AppInfoConfig;
import models.NewSource;
import models.ThirdPartyType;
import models.VulnResults;
import models.result.DefTrackInfo;
import models.SourcesParser;
import models.track.TrackModel;
import models.track.UrlTrackModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.toolkits.scalar.ValueUnitPair;
import utils.SessCallGraphBuilder;
import utils.SessDroidLogger;
import utils.SootUtil;
import utils.VolleyUtils;

import javax.sound.midi.Track;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class SessMain {

    private static long getUsedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    public static void main(String[] args) throws IOException, XmlPullParserException {

        String androidJars = "E:\\adt-bundle-windows-x86_64-20140702\\adt-bundle-windows-x86_64-20140702\\sdk\\platforms";
        String androidJar = "E:\\adt-bundle-windows-x86_64-20140702\\adt-bundle-windows-x86_64-20140702\\sdk\\platforms\\android-26\\android.jar";
        String apkDirPath = "F:\\cyx\\AndroidApp\\googleplay\\s";
        long maxMemoryConsume = -1;
        long alltime = 0;
        int appcount = 0;
        int maxmemorysum = 0;

        SourcesParser sourcesParser = new SourcesParser("setHeaders.txt");

        File apkDir = new File(apkDirPath);
        if (!apkDir.isDirectory()) {
            throw new RuntimeException("Please confirm the apk directory path!");
        }

        String[] dirFiles = apkDir.list((dir, name) -> name.endsWith(".apk"));

        assert dirFiles != null;
        List<String> apkNameList = new ArrayList<>(Arrays.asList(dirFiles));
        VulnResults results = VulnResults.getInstance();

        SessDroidLogger.Warn("Quick Version. (check and change to the flowdroid)");
        
        for (final String apkName :apkNameList)
        {
            maxMemoryConsume = -1;
            final String fullApkPath = apkDirPath + "\\" + apkName;

            SessDroidLogger.Log("Analyzing..." + fullApkPath);
            long start = System.nanoTime();
            boolean isSessionManagementAbled = false;


            if (SootUtil.sootInitAndCGBuild(fullApkPath, androidJar, true)){
                AppInfoConfig config = new AppInfoConfig(apkName, fullApkPath, androidJars);

                isSessionManagementAbled = runAnalysis(config, sourcesParser);
            }
            else {
                SessDroidLogger.Log("Error: call graph built failed. (Out of Memory)" + apkName);
                continue;
            }

            maxMemoryConsume = Math.max(maxMemoryConsume, getUsedMemory());
            long end = System.nanoTime();
            long totalTime = TimeUnit.NANOSECONDS.toSeconds(end - start);

            if (isSessionManagementAbled){
                alltime += totalTime;
                appcount++;
                maxmemorysum += (maxMemoryConsume / 1024 / 1024);
            }

            System.out.println("---------------------------time consuming: " + totalTime + "s---------------------------");
            System.out.println("-----------------------max memory consuming: " + maxMemoryConsume / 1024 / 1024  + "M-----------------------");

            System.out.println("\n\n");

            System.gc();
        }


        System.out.println("=================================dir app ends analysis=================================");
        if (appcount > 0){
            System.out.println("total apps: " + appcount);
            System.out.println("average time consuming: " + alltime / appcount + "s");
            System.out.println("average memory consuming: " + maxmemorysum / appcount + "M");
        }

        results.printAll();
    }

    private static boolean runAnalysis(AppInfoConfig appConfig, SourcesParser sourcesParser) throws IOException {
        Set<TrackModel> sources = new HashSet<>();
        Set<UrlTrackModel> urlInputs = new HashSet<>();
        Set<TrackModel> logInputs = new HashSet<>();
        Set<SootMethod> wrapperLogMeth = new HashSet<>();
        Set<TrackModel> knownGetToken = new HashSet<>();
        Set<SootMethod> wrapperJsonMeth = new HashSet<>();
       /* Set<NewSource> newSources = new HashSet<>();*/

        // 1. iterate first
        for (SootClass sc : Scene.v().getClasses()){
            if (sc.isPhantom())
                continue;
            if (!appConfig.isApplicationClass(sc))
                continue;

            for (SootMethod sm : sc.getMethods()){
                if (!sm.hasActiveBody())
                    continue;
                Body body = sm.retrieveActiveBody();
                for (Unit u : body.getUnits()){
                    Stmt s = (Stmt) u;
                    if (sourcesParser.isContainSourceExpr(u)){

                        if (s.containsInvokeExpr() && scanWrapperHeader((Stmt) u, body) != null){
                            //sourcesParser.addSource(sm.getSignature());
                            /*newSources.add(scanWrapperHeader((Stmt) u, body));*/
                            sourcesParser.addNewSource(scanWrapperHeader((Stmt) u, body));
                            SessDroidLogger.Log("New add source: " + sm.getSignature());
                        }
                    }
                }

            }
        }


        //2.iterate second
        for (SootClass sc : Scene.v().getClasses()){
            if (sc.isPhantom())
                continue;
            if (!appConfig.isApplicationClass(sc))
                continue;

            for (int i = 0; i < sc.getMethods().size(); i++){
                SootMethod sm = sc.getMethods().get(i);
                if (!sm.hasActiveBody())
                    continue;

                //1.volley
                if (sm.getSubSignature().equals("java.util.Map getHeaders()")
                        && VolleyUtils.isVolleyRequestSubClass(sc)
                        && VolleyUtils.headerWithAuthPair(sm) != null){

                    ValueUnitPair pair = VolleyUtils.headerWithAuthPair(sm);
                    sources.add(new TrackModel(sm, pair.getUnit(), pair.getValue()));
                    //TODO URL analysis

                    urlInputs.add(new UrlTrackModel(sm, null, null, ThirdPartyType.VOLLEY_TYPE));

                    logInputs.add(new TrackModel(sm, pair.getUnit(), pair.getValue()));
                }

                else{

                    Iterator<Unit> unitIter = sm.retrieveActiveBody().getUnits().snapshotIterator();
                    while (unitIter.hasNext()){
                        Unit u = unitIter.next();
                        Stmt s = (Stmt) u;

                        if (s.containsInvokeExpr()){
                            InvokeExpr ie = s.getInvokeExpr();


                            if (ie.getArgs().size() > 0
                                    && SootUtil.isAuthKey(ie.getArg(0).toString())){

                                String invokeSig = ie.getMethodRef().getSignature();

                                //TODO 封装的addheader()方法

                                switch (invokeSig) {
                                    case "<okhttp3.Request$Builder: okhttp3.Request$Builder header(java.lang.String,java.lang.String)>":
                                    case "<okhttp3.Request$Builder: okhttp3.Request$Builder addHeader(java.lang.String,java.lang.String)>": {

                                        Value arg = ie.getArg(1);
                                        sources.add(new TrackModel(sm, u, arg, true));

                                        assert ie instanceof InstanceInvokeExpr;
                                        Value base = ((InstanceInvokeExpr) ie).getBase();
                                        urlInputs.add(new UrlTrackModel(sm, u, base, ThirdPartyType.OKHTTP_TYPE));

                                        logInputs.add(new TrackModel(sm, u, arg));

                                        break;
                                    }
                                    case "<com.squareup.okhttp.Request$Builder: com.squareup.okhttp.Request$Builder addHeader(java.lang.String,java.lang.String)>":
                                    case "<com.squareup.okhttp.Request$Builder: com.squareup.okhttp.Request$Builder header(java.lang.String,java.lang.String)>":
                                    case "<org.apache.http.client.methods.HttpGet: setHeader(java.lang.String,java.lang.String)>":
                                    case "<org.apache.http.client.methods.HttpPost: setHeader(java.lang.String,java.lang.String)>":
                                    case "<android.app.DownloadManager$Request: android.app.DownloadManager$Request addRequestHeader(java.lang.String,java.lang.String)>": {
                                        Value arg = ie.getArg(1);
                                        sources.add(new TrackModel(sm, u, arg, true));

                                        logInputs.add(new TrackModel(sm, u, arg));
                                        break;
                                    }
                                    case "<java.net.HttpURLConnection: void setRequestProperty(java.lang.String,java.lang.String)>":
                                    case "<java.net.URLConnection: void setRequestProperty(java.lang.String,java.lang.String)>": {

                                        Value arg = ie.getArg(1);
                                        sources.add(new TrackModel(sm, u, arg, true));

                                        assert ie instanceof InstanceInvokeExpr;
                                        Value base = ((InstanceInvokeExpr) ie).getBase();
                                        urlInputs.add(new UrlTrackModel(sm, u, base, ThirdPartyType.JAVA_NET_CONNECTION));

                                        logInputs.add(new TrackModel(sm, u, arg));
                                        break;
                                    }
                                    case "<com.loopj.android.http.AsyncHttpClient: void addHeader(java.lang.String,java.lang.String)>":
                                    case "<com.loopj.android.http.SyncHttpClient: void addHeader(java.lang.String,java.lang.String)>": {

                                        Value arg = ie.getArg(1);
                                        sources.add(new TrackModel(sm, u, arg, true));

                                        assert ie instanceof InstanceInvokeExpr;
                                        Value base = ((InstanceInvokeExpr) ie).getBase();
                                        urlInputs.add(new UrlTrackModel(sm, u, base, ThirdPartyType.LOOPJ_SYNC));

                                        logInputs.add(new TrackModel(sm, u, arg));
                                        break;
                                    }

                                    case "<com.facebook.AccessToken: java.lang.String getToken()>": {
                                        if (s instanceof AssignStmt){
                                            Value assignLeft = ((AssignStmt) s).getLeftOp();
                                            if (assignLeft instanceof Local){
                                                knownGetToken.add(new TrackModel(sm, u, assignLeft));
                                            }
                                            System.out.println("SessMain WARN: facebook.getToken() leftOp is not a Local");
                                        }
                                        else {
                                            System.out.println("SessMain WARN: facebook.getToken() is not an AssignStmt");
                                        }
                                    }

                                }


                            }


                            if (sourcesParser.containsNewSource(ie) != null){
                                NewSource matchSource = sourcesParser.containsNewSource(ie);

                                int keyIdx = matchSource.getKeyIndex();
                                if (keyIdx == -1){
                                    Value arg = ie.getArg(matchSource.getValueIndex());
                                    sources.add(new TrackModel(sm, u, arg, true));
                                }

                                else {
                                    if (SootUtil.isAuthKey(ie.getArg(keyIdx).toString())){
                                        Value arg = ie.getArg(matchSource.getValueIndex());

                                        sources.add(new TrackModel(sm, u, arg, true));
                                    }
                                }
                            }

                            /*if (isLogWrapperMethod(ie, u, sm)){
                                wrapperLogMeth.add(sm);
                            }*/

                            else if (isJsonObjectWrapperMethod(ie, u, sm)){
                                wrapperJsonMeth.add(sm);
                            }
                            //TODO same enlarge
                            else if (ie.getMethod().getSignature().equals("<com.facebook.AccessToken: java.lang.String getToken()>")
                                    || ie.getMethod().getSignature().equals("<com.google.android.gms.auth.api.signin.GoogleSignInAccount: java.lang.String getIdToken()>")
                                    || ie.getMethod().getSignature().equals("<com.google.firebase.auth.OAuthCredential: java.lang.String getAccessToken()>")){
                                if (s instanceof AssignStmt){
                                    Value left = ((AssignStmt) s).getLeftOp();
                                    if (left instanceof Local){
                                        logInputs.add(new TrackModel(sm, u, left));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        DefTrackInfo defTrackInfo = new DefTrackInfo();

        Set<TrackModel> tokenLocals = new HashSet<>();
        // a. first anti-pattern
        for (TrackModel source : sources){
            BackwardsTrackAnalysis backwardsTrackAnalysis = new BackwardsTrackAnalysis(source, appConfig, defTrackInfo, wrapperJsonMeth);
            backwardsTrackAnalysis.trackAnalysis();

            // d. plainSave anti-pattern
            tokenLocals.addAll(backwardsTrackAnalysis.getComputedLocal());
        }

        ObtainUrlAnalysis urlAnalysis = new ObtainUrlAnalysis(appConfig, Scene.v().getCallGraph());
        // b. second external url anti-pattern
        for (UrlTrackModel urlTrack : urlInputs){
            urlAnalysis.checkSendUrls(urlTrack.getLocateMethod(), urlTrack.getLocateUnit(), urlTrack.getTargetValue(), urlTrack.getType());
        }
        urlAnalysis.dealCollectedUrls();

        // c.Log anti-pattern
        for (TrackModel logModel : logInputs){
            LogAnalysis logAnalysis = new LogAnalysis(logModel, appConfig, wrapperLogMeth);
            logAnalysis.logLeakTrack();
        }

        //d. plainSave anti-pattern
        PlainSaveAnalysis plainSaveAnalysis = new PlainSaveAnalysis(appConfig);
        plainSaveAnalysis.setSourceData(tokenLocals);
        plainSaveAnalysis.setTokenGetSource(setTokenGetSource());
        plainSaveAnalysis.plainSaveAnalysis();

        /*CustomTaintAnalysis taintAnalysis = new CustomTaintAnalysis(appConfig.getAndroidJars(), appConfig.getApkFullPath(), appConfig.getApkName());
        taintAnalysis.runFlowDroid(tokenLocals);*/

        //e. expire analysis
        ExpireAnalysis expireAnalysis = new ExpireAnalysis(appConfig, defTrackInfo.trackedFieldsSigs());
        expireAnalysis.simpleExpireAnalysis();

        return !sources.isEmpty();
    }


    public static boolean isJsonObjectWrapperMethod(InvokeExpr ie, Unit u, SootMethod thisMethod){
        SootMethod callee = ie.getMethod();
        if (callee.getSignature().equals("<org.json.JSONObject: java.lang.String optString(java.lang.String)>")
                || callee.getSignature().equals("<org.json.JSONObject: java.lang.String optString(java.lang.String,java.lang.String)>")
                || callee.getSignature().equals("<org.json.JSONObject: java.lang.String getString(java.lang.String)>")){
            Value arg = ie.getArg(0);
            return isFromIdentity(thisMethod.retrieveActiveBody(), arg, u);
        }
        return false;
    }
    public static Set<String> setTokenGetSource(){
        Set<String> set = new HashSet<>();
        set.add("<com.google.firebase.auth.OAuthCredential: java.lang.String getAccessToken()>");
        set.add("<com.google.android.gms.auth.api.signin.GoogleSignInAccount: java.lang.String getIdToken()>");
        set.add("<com.facebook.AccessToken: java.lang.String getToken()>");
        return set;
    }
    public static boolean isLogWrapperMethod(InvokeExpr ie, Unit u, SootMethod thisMethod){
        SootMethod callee = ie.getMethod();
        if(callee.getSignature().equals("<java.io.PrintStream: void println(java.lang.String)>")
                || callee.getSignature().equals("<java.io.PrintStream: void print(java.lang.String)>")){
            Value arg = ie.getArg(0);
            return isFromIdentity(thisMethod.getActiveBody(), arg, u);
        }

        else {
            String className = callee.getDeclaringClass().getName();
            if (className.startsWith("android.util.Log")){
                if (ie.getArgs().size() > 1 && ie.getArg(1).getType().toString().equals("java.lang.String")){
                    return isFromIdentity(thisMethod.getActiveBody(), ie.getArg(1), u);
                }
            }
            else if (className.startsWith("java.util.logging.Logger")){
                if (callee.getName().equals("warning")
                        || callee.getName().equals("info")){
                    return isFromIdentity(thisMethod.getActiveBody(), ie.getArg(0), u);
                }
                else if (callee.getName().equals("log")){
                    if (ie.getArgs().size() > 1 && ie.getArg(1).getType().toString().equals("java.lang.String")){
                        return isFromIdentity(thisMethod.getActiveBody(), ie.getArg(1), u);
                    }
                }
            }
            else if (className.startsWith("org.slf4j.Logger")) {
                if (ie.getArgs().size() > 0) {
                    for (Value param : ie.getArgs()) {
                        if (param.getType().toString().equals("java.lang.String")) {
                            return isFromIdentity(thisMethod.getActiveBody(), param, u);
                        }
                    }
                }
            }
        }
        return false;
    }

    private static boolean isFromIdentity(Body body, Value value, Unit unit){
        if (!(value instanceof Local))
            return false;

        UnitGraph unitGraph = new ExceptionalUnitGraph(body);
        LocalDefs localDefs = new SimpleLocalDefs(unitGraph);

        List<Unit> defUnits = localDefs.getDefsOfAt((Local) value, unit);
        for (Unit def : defUnits){
            if (def instanceof IdentityStmt){
                return true;
            }
        }
        return false;
    }
    /**
     * unit 是含有addheader("auth", xx)语句的unit
     * @param unit
     * @param locateMethod
     */
    private static NewSource scanWrapperHeader(Stmt stmt, Body body){
        InvokeExpr ie = stmt.getInvokeExpr();
        List<Value> args = ie.getArgs();

        if (args.size() != 2){
            return null;
        }

        int keyIndex = -1;
        int valueIndex = -1;

        UnitGraph unitGraph = new ExceptionalUnitGraph(body);
        SimpleLocalDefs localDefs = new SimpleLocalDefs(unitGraph);

        Value key = args.get(0);
        if (key instanceof Local) {
            Stmt defStmt = SessCallGraphBuilder.getDefinition((Local) key, stmt, localDefs);
            if (defStmt instanceof IdentityStmt) {
                Value right = ((IdentityStmt) defStmt).getRightOp();
                if (right instanceof ParameterRef) {
                    keyIndex = ((ParameterRef) right).getIndex();

                    Value value = args.get(1);
                    if (value instanceof Local) {
                        defStmt = SessCallGraphBuilder.getDefinition((Local) value, stmt, localDefs);

                        if (defStmt instanceof IdentityStmt) {
                            right = ((IdentityStmt) defStmt).getRightOp();

                            if (right instanceof ParameterRef) {
                                valueIndex = ((ParameterRef) right).getIndex();

                                return new NewSource(keyIndex, valueIndex, body.getMethod());
                            }
                        }
                    }
                }
            }
        }
        else if (key instanceof StringConstant){
            if (((StringConstant) key).value.toLowerCase().contains("auth")
                    || ((StringConstant) key).value.toLowerCase().contains("token")){
                Value value = args.get(1);

                if (value instanceof Local){
                    Stmt defStmt = SessCallGraphBuilder.getDefinition((Local) value, stmt, localDefs);

                    if (defStmt instanceof IdentityStmt) {
                        Value right = ((IdentityStmt) defStmt).getRightOp();

                        if (right instanceof ParameterRef) {
                            valueIndex = ((ParameterRef) right).getIndex();

                            return new NewSource(keyIndex, valueIndex, body.getMethod());
                        }
                    }
                }
            }

        }
        return null;
    }
}

