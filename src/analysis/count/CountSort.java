package analysis.count;

import org.xmlpull.v1.XmlPullParserException;
import polyglot.ast.For;
import soot.Scene;
import soot.SootClass;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import utils.SootUtil;
import utils.UnzipApkTool;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CountSort {

    public static void main(String[] args) throws IOException, XmlPullParserException {
        String apkDirPath = "";
        String androidJar = "";


        File apkDir = new File(apkDirPath);
        if (!apkDir.isDirectory()) {
            throw new RuntimeException("Please confirm the apk directory path!");
        }

        String[] dirFiles = apkDir.list((dir, name) -> name.endsWith(".apk"));

        assert dirFiles != null;
        List<String> apkNameList = new ArrayList<>(Arrays.asList(dirFiles));


        for (final String apkName :apkNameList) {

            final String fullApkPath = apkDirPath + "\\" + apkName;

            SootUtil.sootInitAndCGBuild(fullApkPath, androidJar, false);

            int[] involved  = getInvolvedPackages();

        }

    }

    private static int[] getInvolvedPackages(){
        int[] result = new int[5];

        for (SootClass sc : Scene.v().getApplicationClasses()){
            if (sc.getName().startsWith("okhttp3.")){
                result[0] = 1;
            }
            else if (sc.getName().startsWith("retrofit2.")){
                result[1] = 1;
            }
            else if (sc.getName().startsWith("org.apache.http.")){
                result[2] = 1;
            }
            else if (sc.getName().startsWith("java.net.")){
                result[3] = 1;
            }
            else if (sc.getName().startsWith("com.loopj.android.http")){
                result[4] = 1;
            }
        }
        return result;
    }

}
