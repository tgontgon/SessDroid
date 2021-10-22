package configs;

import java.io.File;

public class MyConstants {
    public static String apkName;//TODO Getter and Setter

    /**
     * create [multiClasses] dir in basePath
     * @param basePath apk dir
     * @param i dex index
     * @return [multiClasses] path
     */
    public static String getMultiDexName(String basePath, int i){
        File dir = new File(basePath + "/[MultiClasses]");
        if (!dir.exists()){
            dir.mkdir();
        }
        return "/[MultiClasses]/" + apkName + "_classes" + i + ".dex";
    }


}
