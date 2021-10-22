package analysis.expire;

import soot.jimple.infoflow.android.axml.AXmlHandler;
import soot.jimple.infoflow.android.axml.AXmlNode;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferUnderflowException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ApkLayoutHandler {
    private File apk;
    private ZipFile zip;
    private Set<String> clickMethods;

    public ApkLayoutHandler(String path) throws IOException {
        this(new File(path));
    }
    public ApkLayoutHandler(File apkFile) throws IOException {
        this.apk = apkFile;
        this.zip = new ZipFile(apk);
        this.clickMethods = new HashSet<>();
    }


    private void loadClickMethodsSpec(AXmlNode node){
        if (node == null){
            return;
        }
        if (node.hasAttribute("onClick")){
            clickMethods.add((String) node.getAttribute("onClick").getValue());
            return;
        }

        Iterator var7 = node.getChildren().iterator();

        while(var7.hasNext()) {
            AXmlNode childNode = (AXmlNode)var7.next();
            loadClickMethodsSpec(childNode);
        }

    }

    /**
     * 加载所有layout文件的click methods
     * @throws IOException
     */
    public void loadClickMethods() throws IOException {
        InputStream is;

        Enumeration entries = this.zip.entries();

        while(entries.hasMoreElements()) {
            ZipEntry entry = (ZipEntry)entries.nextElement();
            String entryName = entry.getName();

            if (entryName.startsWith("res/layout/")) {
                is = this.zip.getInputStream(entry);


                AXmlHandler handler = null;
                try {
                     handler = new AXmlHandler(is);
                }catch (BufferUnderflowException e){
                    e.printStackTrace();
                }

                if (handler == null){
                    return;
                }
                AXmlNode rootNode = handler.getDocument().getRootNode();
                loadClickMethodsSpec(rootNode);

            }
        }
    }

    /**
     * 从指定的fileName中获取inputstream
     * @param filename
     * @return
     * @throws IOException
     */
    public InputStream getInputStream(String filename) throws IOException {
        InputStream is = null;

        Enumeration entries = this.zip.entries();

        while(entries.hasMoreElements()) {
            ZipEntry entry = (ZipEntry)entries.nextElement();
            String entryName = entry.getName();
            if (entryName.equals(filename)) {
                is = this.zip.getInputStream(entry);
                break;
            }
        }

        return is;
    }

    public Set<String> getClickMethods() {
        return clickMethods;
    }
}
