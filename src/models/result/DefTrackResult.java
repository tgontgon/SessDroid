package models.result;

import models.SharedPreModel;
import models.track.TrackModel;
import soot.SootField;

import java.util.HashSet;
import java.util.Set;

/**
 * 一个app 一个result, 好几个startpoint，一个startpoint跟着很多tracktrace
 */
public class DefTrackResult {
    private TrackModel startPoint;
    private Set<SootField> trackedFields;
    private Set<String> trackedInvokes;
    private Set<String> trackedCallee;
    private Set<SharedPreModel> savedSps;

    public DefTrackResult(TrackModel startPoint){
        this.startPoint = startPoint;
        this.trackedInvokes = new HashSet<>();
        this.trackedFields = new HashSet<>();
        this.trackedCallee = new HashSet<>();
        this.savedSps = new HashSet<>();
    }

    public boolean addTrackedFieldPiece(SootField piece){
        if (trackedFields.contains(piece)){
            return false;
        }
        else {
            trackedFields.add(piece);
            return true;
        }
    }

    public boolean addTrackedCallee(String piece){
        if (trackedCallee.contains(piece))
            return false;
        else {
            trackedCallee.add(piece);
            return true;
        }
    }
    public boolean addTrackedInvokePiece(String piece){
        if (trackedInvokes.contains(piece)){
            return false;
        }
        else {
            trackedInvokes.add(piece);
            return true;
        }
    }
    public Set<String> getTrackedCallee(){
        return trackedCallee;
    }

    public boolean addSavedSpPiece(SharedPreModel spPiece){
        if (savedSps.contains(spPiece)){
            return false;
        }
        else {
            savedSps.add(spPiece);
            return true;
        }
    }
    public Set<SootField> getTrackedFields() {
        return trackedFields;
    }

    public Set<String> getTrackedInvokes() {
        return trackedInvokes;
    }

    public Set<SharedPreModel> getSavedSps() {
        return savedSps;
    }

    public TrackModel getStartPoint() {
        return startPoint;
    }
}
