import analysis.save.PlainSaveAnalysis;
import com.sun.xml.internal.bind.v2.schemagen.xmlschema.Appinfo;
import configs.AppInfoConfig;
import fj.data.Array;
import models.track.TrackModel;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.problems.BackwardsInfoflowProblem;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.scalar.ValueUnitPair;
import utils.SessDroidLogger;
import utils.SootUtil;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class Main {
    private static final String androidJars = "E:\\adt-bundle-windows-x86_64-20140702\\adt-bundle-windows-x86_64-20140702\\sdk\\platforms";
    private static final String androidJar = "E:\\adt-bundle-windows-x86_64-20140702\\adt-bundle-windows-x86_64-20140702\\sdk\\platforms\\android-26\\android.jar";
    private static final String apkDirPath = "F:\\cyx\\AndroidApp\\sessionmechanism";
    private static final String apkName = "theleague1.17.756";


    public static void main(String[] args) throws IOException, XmlPullParserException {

        String apkPath = apkDirPath + File.separator + apkName + ".apk";
        SootUtil.sootInitAndCGBuild(apkPath, androidJar, false);
        AppInfoConfig config = new AppInfoConfig(apkName, apkPath, androidJars);
        testType(config);

        //String apkDirPath = "F:\\cyx\\AndroidApp\\sessionmechanism";
        //String apkDirPath = "E:\\AndroidStudioProjects\\NetworkMix\\app\\build\\outputs\\apk\\debug";

        /*File apkDir = new File(apkDirPath);
        if (!apkDir.isDirectory()) {
            throw new RuntimeException("Please confirm the apk directory path!");
        }

        String[] dirFiles = apkDir.list((dir, name) -> name.endsWith(".apk"));

        assert dirFiles != null;
        List<String> apkNameList = new ArrayList<>(Arrays.asList(dirFiles));


        for (final String apkName :apkNameList) {
            final String fullApkPath = apkDirPath + "\\" + apkName;

            if (!fullApkPath.contains("amazon-prime-video"))
                continue;

            SessDroidLogger.Log("Analyzing..." + fullApkPath);
            SootUtil.sootInitAndCGBuild(fullApkPath, androidJar,true);
            AppInfoConfig config = new AppInfoConfig(apkName, fullApkPath, androidJars);

            testCallgraph();
        }*/
    }



    private static void testType(AppInfoConfig config){
        for (SootClass sc : Scene.v().getApplicationClasses()){
            if (!sc.getName().startsWith("com.league.")){
                continue;
            }

            for (SootMethod sm : sc.getMethods()){
                if (!sm.hasActiveBody())
                    continue;

                for (Unit u : sm.retrieveActiveBody().getUnits()){
                    if (u.toString().contains("<com.facebook.AccessToken: java.lang.String getToken()>")){
                        System.out.println(u + " " + sm.getSignature());
                    }
                }
            }
        }
    }


    private static void testSuper(){
        SootClass sc = Scene.v().getSootClass("com.league.theleague.network.CurrentSession$6");
        for (SootMethod sm : sc.getMethods()){
            System.out.println(sm.getSignature());
        }
    }

    private static void testUnit(){
        List<Unit> units = new ArrayList<>();
        SootMethod method = Scene.v().getMethod("<com.league.theleague.network.CurrentSession: void setPicassoInstance()>");
        for (Unit unit : method.getActiveBody().getUnits()) {
            if (unit.toString().contains("$r0 = virtualinvoke $r0.<okhttp3.OkHttpClient$Builder: okhttp3.OkHttpClient$Builder addInterceptor(okhttp3.Interceptor)>($r1)"))
            {
                Stmt stmt = (Stmt) unit;
                System.out.println(stmt.getInvokeExpr().getArg(0).getType().toString());
            }
        }
    }


    private static void testCallgraph(){
        CallGraph cg = Scene.v().getCallGraph();
        SootMethod method = Scene.v().getMethod("<com.amazon.avod.http.internal.BearerToken$SuccessValues: void <init>(java.lang.String,long)>");

        for (Iterator<Edge> it = cg.edgesInto(method); it.hasNext(); ) {
            Edge context = it.next();
            SootMethod caller = context.src();
            System.out.println(caller.getSignature());
            System.out.println(context.srcUnit());
            System.out.println();
            System.out.println();

            for (Iterator<Edge> ite = cg.edgesInto(caller);ite.hasNext();){
                Edge edge = ite.next();
                SootMethod calerler = edge.src();
                System.out.println(calerler.getSignature());
                System.out.println(edge.srcUnit());
                System.out.println();
            }
        }
    }



    private static CallGraph getFlowdroidCallgraph(String apkPath, String androidJars){
        InfoflowAndroidConfiguration configuration = new InfoflowAndroidConfiguration();
        configuration.setMergeDexFiles(true);
        configuration.getAnalysisFileConfig().setAndroidPlatformDir(androidJars);
        configuration.getAnalysisFileConfig().setTargetAPKFile(apkPath);

        SetupApplication app = new SetupApplication(configuration);
        app.constructCallgraph();
        return Scene.v().getCallGraph();
    }
}
