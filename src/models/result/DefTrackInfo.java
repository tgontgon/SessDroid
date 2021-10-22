package models.result;

import models.SharedPreModel;
import models.result.DefTrackResult;
import soot.SootField;

import java.util.HashSet;
import java.util.Set;

public class DefTrackInfo {
    Set<DefTrackResult> trackResults;

    public DefTrackInfo(){
        this.trackResults = new HashSet<>();
    }
    public void addDefTrackResult(DefTrackResult resultPiece){
        this.trackResults.add(resultPiece);
    }
    public Set<SootField> trackedFieldsSigs(){
        Set<SootField> fieldsSig = new HashSet<>();
        for (DefTrackResult result : trackResults){
            fieldsSig.addAll(result.getTrackedFields());
        }
        return fieldsSig;
    }


    public Set<String> trackedInvokeSigs(){
        Set<String> invokeSig = new HashSet<>();
        for (DefTrackResult result : trackResults){
            invokeSig.addAll(result.getTrackedInvokes());
        }
        return invokeSig;
    }

}
