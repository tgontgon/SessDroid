package analysis.urlAnalysis.specific;

import configs.AppInfoConfig;
import models.track.TrackModel;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.SimpleLocalDefs;
import utils.VolleyUtils;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class VolleyManager {
    public class URLConstructionWithIndex{
        private SootMethod initMethod;
        private int urlIndex;
        public URLConstructionWithIndex(SootMethod iniMethod, int index){
            this.initMethod = iniMethod;
            this.urlIndex = index;
        }

        public SootMethod getInitMethod() {
            return initMethod;
        }

        public int getUrlIndex() {
            return urlIndex;
        }

        @Override
        public String toString() {
            return "urlIndex: " + urlIndex + " in cons method: " + initMethod.getSignature();
        }
    }

    private SootClass requestClass;
    private AppInfoConfig info;
    private CallGraph callGraph;

    public VolleyManager(CallGraph callGraph, AppInfoConfig info, SootClass requestClass){
        this.requestClass = requestClass;
        this.info = info;
        this.callGraph = callGraph;
    }

    /**
     *  main method
     * @return
     */
    public Set<TrackModel> getVolleyClientUrls(){
        System.out.println("Start VolleyManager analysis... " + requestClass.getName());

        Set<TrackModel> set = new HashSet<>();
        //Map<SootMethod, ValueUnitPair> map = new HashMap<>();

        SootMethod initMeth = null;
        for (SootMethod sm : requestClass.getMethods()){
            if (sm.isConstructor()){
                initMeth = sm;
            }
        }

        if (initMeth != null){
            int urlParamIndex = getVolleyRequestParamIndex(initMeth);
            /*Set<URLConstructionWithIndex> cons = new HashSet<>();
            cons.add(new URLConstructionWithIndex(initMeth, urlParamIndex));*/

            Set<MethodOrMethodContext> invokeInitPieces = getCallers(initMeth);
            for (MethodOrMethodContext invokeInitPiece : invokeInitPieces){
                SootMethod loMeth = invokeInitPiece.method();
                Stmt invokeStmt = (Stmt) invokeInitPiece.context();
                assert invokeStmt.containsInvokeExpr();
                Value url = invokeStmt.getInvokeExpr().getArg(urlParamIndex);

                set.add(new TrackModel(loMeth, invokeStmt, url));
            }

        }
        else{
            System.err.println("Can't find the init method in "+ requestClass.getName());
            return null;
        }

        return set;

    }


    public static int getVolleyRequestParamIndex(SootMethod initMeth) {
        Unit initUnit = getVolleyConstructUnit(initMeth);

        assert initUnit instanceof InvokeStmt;
        InvokeExpr ie = ((InvokeStmt) initUnit).getInvokeExpr();

        SootMethod invokeMe = ie.getMethod();
        UnitGraph unitGraph = new BriefUnitGraph(initMeth.getActiveBody());
        LocalDefs localDefs = new SimpleLocalDefs(unitGraph);
        List<Unit> defUnits;


        if (invokeMe.getSignature().equals("<com.android.volley.Request: void <init>(java.lang.String,com.android.volley.Response$ErrorListener)>")){
            defUnits = localDefs.getDefsOfAt((Local) ie.getArg(0), initUnit);
        }
        else if ((invokeMe.getSignature().equals("<com.android.volley.Request: void <init>(int,java.lang.String,com.android.volley.Response$ErrorListener)>"))) {
            defUnits = localDefs.getDefsOfAt((Local) ie.getArg(1), initUnit);
        }
        else {
            defUnits = localDefs.getDefsOfAt((Local) ie.getArg(getVolleyRequestParamIndex(invokeMe)), initUnit);
        }

        IdentityStmt defStmt = (IdentityStmt) defUnits.get(0);

        ParameterRef pRef = (ParameterRef) defStmt.getRightOp();
        return pRef.getIndex();
    }


    private static Unit getVolleyConstructUnit(SootMethod sm) {
        if (!sm.hasActiveBody())
            throw new RuntimeException(sm + " has no active body!");
        for (Unit unit : sm.getActiveBody().getUnits()) {
            Stmt stmt = (Stmt) unit;
            if (stmt.containsInvokeExpr()) {
                InvokeExpr ie = stmt.getInvokeExpr();
                if (ie.getMethod().getSubSignature().contains("void <init>")
                        && VolleyUtils.isVolleyRequestSubClass(ie.getMethod().getDeclaringClass())) {
                    return unit;
                }
            }
        }
        return null;
    }

    private Set<MethodOrMethodContext> getCallers(SootMethod callee){
        Set<MethodOrMethodContext> callingInfo = new HashSet<>();

        Iterator<Edge> ite = callGraph.edgesInto(callee);
        while (ite.hasNext()){
            Edge edge = ite.next();
            Unit callingUnit = edge.srcUnit();
            SootMethod caller = edge.src();
            callingInfo.add(MethodContext.v(caller, callingUnit));
        }
        return callingInfo;
    }
}
