package test;

import analysis.defTrack.BackwardsTrackAnalysis;
import configs.AppInfoConfig;
import models.result.DefTrackInfo;
import models.track.TrackModel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class BackwardsTrackAnalysisTest {

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void trackAnalysis(TrackModel input, AppInfoConfig appConfig, DefTrackInfo trackInfo, Set< SootMethod > wrapperJsonMeths, CallGraph callGraph) {
        BackwardsTrackAnalysis backwardsTrackAnalysis = new BackwardsTrackAnalysis(input, appConfig, callGraph, trackInfo, wrapperJsonMeths);
        backwardsTrackAnalysis.trackAnalysis();
    }
}