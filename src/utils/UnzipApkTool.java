package utils;

import configs.MyConstants;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class UnzipApkTool {

    public static void invokePackage(String apkFilePath){
        String clonePath = copyAPKZip(apkFilePath);

        FileInputStream fis = null;
        ZipInputStream zis = null;
        ZipEntry zentry = null;

        try {
            fis = new FileInputStream(clonePath);
            zis = new ZipInputStream(fis);

            int i = 2;
            while ((zentry = zis.getNextEntry()) != null){
                String fileNameToUnzip = zentry.getName();

                System.out.println(fileNameToUnzip);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void unzipApk(String apkDirPath, String apkFilePath) throws IOException {
        String clonePath = copyAPKZip(apkFilePath);

        FileInputStream fis = null;
        ZipInputStream zis = null;
        ZipEntry zentry = null;

        try {
            fis = new FileInputStream(clonePath);
            zis = new ZipInputStream(fis);

            int i = 2;
            while ((zentry = zis.getNextEntry()) != null){
                String fileNameToUnzip = zentry.getName();

                if (fileNameToUnzip.contains(".dex") && !fileNameToUnzip.contains("classes.dex")){
                    File targetFile = new File(apkDirPath + MyConstants.getMultiDexName(apkDirPath, i++));
                    unzipEntry(zis, targetFile);
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            if (zis != null)
                zis.close();

            if (fis != null)
                fis.close();

            File clone = new File(clonePath);
            clone.delete();
        }

    }

    public static String copyAPKZip(String path){
        try {
            FileInputStream fis = new FileInputStream(path);
            FileOutputStream fos = new FileOutputStream(path.replace("apk", "zip"));

            byte[] data = new byte[1024];
            int length = 0;
            while((length = fis.read(data)) > 0)
            {
                fos.write(data, 0 , length);
            }
            fis.close();
            fos.close();
        }catch (IOException e){
            e.printStackTrace();
        }

        return path.replace("apk", "zip");
    }

    private static File unzipEntry(ZipInputStream zis, File targetFile) throws IOException {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(targetFile);
            byte[] buffer = new byte[1024*2];
            int len = 0;
            while ((len = zis.read(buffer)) != -1)
            {
                fos.write(buffer, 0, len);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (fos != null){
                fos.close();
            }
        }
        return targetFile;
    }
}
