package test;

import analysis.pointsTo.CustomTaintAnalysis;
import analysis.pointsTo.LocalStatementParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import soot.jimple.infoflow.sourcesSinks.definitions.ISourceSinkDefinition;
import soot.jimple.infoflow.sourcesSinks.definitions.ISourceSinkDefinitionProvider;
import soot.toolkits.scalar.UnitValueBoxPair;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CustomTaintAnalysisTest {

    String androidJars = "E:\\adt-bundle-windows-x86_64-20140702\\adt-bundle-windows-x86_64-20140702\\sdk\\platforms";
    String apkFile = "F:\\cyx\\AndroidApp\\sessionmechanism\\theleague1.17.756.apk";
    String apkName = "theLeague";

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void runFlowDroid() throws IOException {
        CustomTaintAnalysis analysis = new CustomTaintAnalysis(androidJars, apkFile, apkName);
        analysis.runFlowDroid(new HashSet<>());

        Iterator<? extends ISourceSinkDefinition> ite = analysis.getSourceSink().getSources().iterator();
        while (ite.hasNext()){
            System.out.println(ite.next());
        }


    }
}