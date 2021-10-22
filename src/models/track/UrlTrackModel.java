package models.track;

import models.ThirdPartyType;
import soot.SootMethod;
import soot.Unit;
import soot.Value;


public class UrlTrackModel extends TrackModel {

    private ThirdPartyType type;

    public UrlTrackModel(SootMethod sm, Unit u, Value value, ThirdPartyType type){
        super(sm, u, value);
        this.type = type;
    }

    public ThirdPartyType getType() {
        return type;
    }
}
