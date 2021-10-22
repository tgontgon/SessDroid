package analysis.pointsTo;

import models.VulnResults;
import models.track.TrackModel;
import soot.ValueBox;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.sourcesSinks.definitions.ISourceSinkDefinitionProvider;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.toolkits.scalar.UnitValueBoxPair;
import soot.toolkits.scalar.ValueUnitPair;
import soot.util.MultiMap;
import utils.SessDroidLogger;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

public class CustomTaintAnalysis {
    private String apkFileLocation;
    private String androidJars;
    private String apkName;
    private ISourceSinkDefinitionProvider sourceSink;

    public CustomTaintAnalysis(String androidJars, String apkFile, String apkName) {
        this.androidJars = androidJars;
        this.apkFileLocation = apkFile;
        this.apkName = apkName;
    }

    private ISourceSinkDefinitionProvider createSourceSinkProvider(Map<ValueUnitPair, String> sources, String sourceSinkFile) throws IOException {
        ISourceSinkDefinitionProvider sourceSinks = LocalStatementParser.fromFile(sources, sourceSinkFile);
        this.sourceSink = sourceSinks;
        return sourceSinks;
    }

    public void runFlowDroid(Set<TrackModel> fieldSources) throws IOException {
        Map<ValueUnitPair, String> map = new HashMap<>();
        for (TrackModel trackModel : fieldSources){
            map.put(new ValueUnitPair(trackModel.getTargetValue(), trackModel.getLocateUnit()), trackModel.getLocateMethod().getSignature());
        }
        runFlowDroid(map);
    }

    public void runFlowDroid(Map<ValueUnitPair, String> sources) throws IOException {
        if (sourceSink == null) {
            sourceSink = createSourceSinkProvider(sources, "SourcesAndSinks.txt");
            System.out.println("Start taint analysis with...");
        }

        InfoflowAndroidConfiguration configuration = new InfoflowAndroidConfiguration();
        configuration.setMergeDexFiles(true);
        configuration.getAnalysisFileConfig().setAndroidPlatformDir(androidJars);
        configuration.getAnalysisFileConfig().setTargetAPKFile(apkFileLocation);
        configuration.getAccessPathConfiguration().setAccessPathLength(3);
        configuration.setFlowSensitiveAliasing(false);
        configuration.setEnableExceptionTracking(false);
        configuration.setDataFlowTimeout(1000);
        configuration.getCallbackConfig().setCallbackAnalysisTimeout(1000);

        SetupApplication app = new SetupApplication(configuration);
        app.setTaintWrapper(new EasyTaintWrapper("E:\\IdeaProjects\\SessDroid\\EasyTaintWrapperSource.txt"));

        InfoflowResults result = app.runInfoflow(sourceSink);

        MultiMap<ResultSinkInfo, ResultSourceInfo> ite = result.getResults();
        if (ite == null){
            return;
        }
        for (ResultSinkInfo sinkInfo : ite.keySet()){
            Stmt sinkStmt = sinkInfo.getStmt();
            if (isLogSink(sinkStmt.toString())){
                SessDroidLogger.Info("Find Leak through LOG Defect.");
                VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.LEAK_THROUGH_LOG, apkName);
            }
            else{
                SessDroidLogger.Info("Find Plain Storage Defect.");
                VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.PLAIN_SAVE_TOKEN, apkName);
            }
        }
    }

    /**
     *
     * @param stmtStr
     * @return true
     */
    private boolean isLogSink(String stmtStr) {
        String str = stmtStr.toLowerCase();
        if (str.contains("log") || str.contains("write")){
            return true;
        }
        return false;
    }

    public String getApkFileLocation() {
        return apkFileLocation;
    }

    public void setApkFileLocation(String apkFileLocation) {
        this.apkFileLocation = apkFileLocation;
    }

    public String getAndroidJars() {
        return androidJars;
    }

    public void setAndroidJars(String androidJars) {
        this.androidJars = androidJars;
    }

    public String getApkName() {
        return apkName;
    }

    public void setApkName(String apkName) {
        this.apkName = apkName;
    }

    public ISourceSinkDefinitionProvider getSourceSink() {
        return sourceSink;
    }

    public void setSourceSink(ISourceSinkDefinitionProvider sourceSink) {
        this.sourceSink = sourceSink;
    }
}
