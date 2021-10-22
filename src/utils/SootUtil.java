package utils;


import configs.MyConstants;
import exceptions.UnzipApkException;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.jimple.infoflow.entryPointCreators.IEntryPointCreator;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;
import soot.toolkits.scalar.ConstantValueToInitializerTransformer;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class SootUtil {

    /**
     * sootInitializer and generate call graph
     * @param apkFileLocation
     * @param androidJar
     * @return
     */
    public static boolean sootInitAndCGBuild(String apkFileLocation, String androidJar, boolean isBuildCg){
        soot.G.reset();

        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_soot_classpath(apkFileLocation + File.pathSeparator + androidJar);

        /*if (!loadMultiDexFiles(apkFileLocation)){
            throw new UnzipApkException();
        }*/

        Options.v().set_process_dir(Collections.singletonList(apkFileLocation));
        Options.v().set_force_android_jar(androidJar);
        Options.v().set_whole_program(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().setPhaseOption("cg.spark", "on");
        Options.v().set_output_format(Options.output_format_none);


        Options.v().set_wrong_staticness(Options.wrong_staticness_fix);
        try{
            Scene.v().loadNecessaryClasses();
            PackManager.v().runPacks();

            for (SootClass sc : Scene.v().getApplicationClasses()) {
                if (!sc.isPhantom())
                    ConstantValueToInitializerTransformer.v().transformClass(sc);
            }
        }catch (RuntimeException error){
            return false;
        }
        if (!isBuildCg)
            return true;

        SessCallGraphBuilder.retrieveActiveBodies();

        CallGraph callGraph = SessCallGraphBuilder.buildAndGet();
        Scene.v().setCallGraph(callGraph);

        return true;
    }

    /**
     * set multiple dex files for process_dir
     * @param apkFilePath apk file location
     * @return successfully load
     */
    private static boolean loadMultiDexFiles(String apkFilePath) {
        List<String> processFiles = new LinkedList<>();
        String basicPath = apkFilePath.substring(0, apkFilePath.lastIndexOf(File.separator));//apk dir path

        try{
            UnzipApkTool.unzipApk(basicPath, apkFilePath);
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        for (int i = 2; i < 20; i++){
            String dexPath = basicPath + MyConstants.getMultiDexName(basicPath, i);

            if (new File(dexPath).exists()){
                SessDroidLogger.Info("additional dex file: " + dexPath);
                processFiles.add(dexPath);
            }
            else
                break;
        }

        if(processFiles.size() > 0) {
            Options.v().set_process_dir(processFiles);
        }
        return true;
    }

    /**
     * 判断key value的key是否是携带token的value
     * @param keyStr
     * @return
     */
    public static boolean isAuthKey(String keyStr) {
        if (keyStr.toUpperCase().contains("X-CRASHLYTICS-DEVELOPER-TOKEN")
                || keyStr.toLowerCase().contains("authserver")
                || keyStr.toLowerCase().contains("authversion")
                || keyStr.toLowerCase().contains("flow")){
            return false;
        }

        return keyStr.toLowerCase().contains("token")
                || keyStr.toLowerCase().contains("auth")
                || keyStr.toLowerCase().contains("bearer")
                //|| keyStr.toLowerCase().contains("cookie")
                || keyStr.toLowerCase().contains("session");
    }

}
