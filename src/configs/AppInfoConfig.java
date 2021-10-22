package configs;

import org.xmlpull.v1.XmlPullParserException;
import soot.SootClass;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.toolkits.callgraph.CallGraph;

import java.io.IOException;

public class AppInfoConfig {
    private String apkFullPath;
    private ProcessManifest manifest;
    private String appPackName;
    private String androidJars;
    private CallGraph callGraph;
    private String apkName;


    public AppInfoConfig(String apkName, String apkFullPath, String androidJars) throws IOException, XmlPullParserException {
        this(apkName, apkFullPath, androidJars, null);
    }

    public AppInfoConfig(String apkName,String apkFullPath, String androidJars, CallGraph callGraph) throws IOException, XmlPullParserException {
        this.apkFullPath = apkFullPath;
        this.manifest = new ProcessManifest(apkFullPath);
        this.callGraph = callGraph;
        this.androidJars = androidJars;
        this.appPackName = manifest.getPackageName();
        this.apkName = apkName;
    }


    public boolean isApplicationClass(SootClass sootClass){
        return sootClass.isApplicationClass() && !sootClass.getName().startsWith("okhttp")
                && !sootClass.getName().startsWith("retrofit")
                && !sootClass.getName().startsWith("org.apache.http.")
                && !sootClass.getName().startsWith("com.loopj.android.")
                && !sootClass.getName().startsWith("android.")
                && !sootClass.getName().startsWith("com.android.volley.")
                && !sootClass.getName().startsWith("com.twitter.sdk.")
                && !sootClass.getName().startsWith("com.google.firebase")
                && !sootClass.getName().startsWith("io.fabric.sdk.android.")
                && !sootClass.getName().startsWith("com.amazon.identity.auth.")
                && !sootClass.getName().startsWith("com.squareup.okhttp")
                && !sootClass.getName().startsWith("com.alipay.sdk")
                && !sootClass.getName().startsWith("com.facebook.")
                && !sootClass.getName().startsWith("kotlin.")
                && !sootClass.getName().startsWith("com.tencent.")
                && !sootClass.getName().startsWith("com.cellpointmobile.sdk");
    }


    public String getAppPackName() {
        return appPackName;
    }

    public void setAppPackName(String appPackName) {
        this.appPackName = appPackName;
    }

    public String getApkFullPath() {
        return apkFullPath;
    }

    public String getAndroidJars() {
        return androidJars;
    }

    public CallGraph getCallGraph() {
        return callGraph;
    }

    public static boolean isClassInSystemPackage(String className) {
        return className.startsWith("android.") || className.startsWith("java.")
                || className.startsWith("javax.")
                || className.startsWith("sun.")
                || className.startsWith("org.codehaus.jackson.")
                || className.startsWith("org.jsoup.")
                || className.startsWith("com.google.");
    }

    public String getApkName() {
        return apkName;
    }
}
