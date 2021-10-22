package models.track;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.toolkits.callgraph.SlowCallGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;

import java.util.Objects;

public class TrackModel {
    private SootMethod locateMethod;
    private ExceptionalUnitGraph unitGraph;
    private Unit locateUnit;
    private Value targetValue;
    private boolean isSource;



    public TrackModel(SootMethod locateMethod, Unit locateUnit, Value targetValue){
        this(locateMethod, locateUnit, targetValue, false);
    }


    public TrackModel(SootMethod locateMethod, Unit locateUnit, Value targetValue, boolean isSource){
        this(locateMethod, locateUnit, targetValue, null, isSource);
    }

    public TrackModel(SootMethod locateMethod, Unit locateUnit, Value targetValue, ExceptionalUnitGraph unitGraph, boolean isSource){
        this.locateMethod = locateMethod;
        this.locateUnit = locateUnit;
        this.targetValue = targetValue;
        this.isSource = isSource;
        if (unitGraph == null)
            this.unitGraph = locateMethod.hasActiveBody() ? new ExceptionalUnitGraph(locateMethod.retrieveActiveBody()) : null;
        else {
            this.unitGraph = unitGraph;
        }

    }

    public ExceptionalUnitGraph getUnitGraph(){
        return this.unitGraph;
    }

    public SootMethod getLocateMethod() {
        return locateMethod;
    }

    public Unit getLocateUnit() {
        return locateUnit;
    }

    public Value getTargetValue() {
        return targetValue;
    }

    public boolean isSource(){
        return this.isSource;
    }
    public String toString(){
        if (isSource)
            return "*S*(" + targetValue + ")" + locateUnit + " in " + locateMethod;
        else
            return "(" + targetValue + ")" + locateUnit + " in " + locateMethod;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrackModel model = (TrackModel) o;
        return isSource == model.isSource &&
                Objects.equals(locateMethod, model.locateMethod) &&
                Objects.equals(unitGraph, model.unitGraph) &&
                Objects.equals(locateUnit, model.locateUnit) &&
                Objects.equals(targetValue, model.targetValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(locateMethod, unitGraph, locateUnit, targetValue, isSource);
    }
}
