package analysis.urlAnalysis.specific;



import configs.AppInfoConfig;
import exceptions.NullReturnOpException;
import models.track.TrackModel;
import org.jf.dexlib2.iface.Field;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.*;

import javax.sound.midi.Track;
import java.util.*;

public class JavaNetManager {
    private static String URI_TO_URL_SIG = "<java.net.URI: java.net.URL toURL()>";
    private static String URL_OPEN_CONNECTION_METH_SIG = "<java.net.URL: java.net.URLConnection openConnection()>";
    private static String URL_INIT_METH_SIG = "<java.net.URL: void <init>(java.lang.String)>";

    private Logger mLogger;
    private AppInfoConfig info;
    private CallGraph cg;

    private Set<MethodOrMethodContext> computedCallers;
    private Set<MethodOrMethodContext> computedCallees;
    private Set<TrackModel> computedFields;

    public JavaNetManager(AppInfoConfig info, CallGraph callGraph){
        this.mLogger = LoggerFactory.getLogger("JavaNetUrlManager ");
        this.info = info;
        this.cg = callGraph;
        this.computedCallers = new HashSet<>();
        this.computedCallees = new HashSet<>();
        this.computedFields = new HashSet<>();
    }

    /*public Set<TrackModel> getJavaNetUrls(SootMethod sootMethod, Unit u, Value con){
        System.out.println("Start JavaNetManager analysis... " + u + " in " + sootMethod);
        Set<TrackModel> urlStrModel = new HashSet<>();

        Set<TrackModel> uris = getTargetInvokeBase(sootMethod, null, u, con);
        for (TrackModel uri : uris){
            urlStrModel.addAll(findUrlInitStr(uri.getLocateMethod(), uri.getUnitGraph(), uri.getLocateUnit(), uri.getTargetValue()));
        }

        return
    }*/
    public Set<TrackModel> getJavaNetUrls(SootMethod sootMethod, Unit u, Value con){

        Set<TrackModel> resSet = new HashSet<>();
        Set<MethodOrMethodContext> addSet = getTargetInitUrl(sootMethod, u, con, URL_OPEN_CONNECTION_METH_SIG);

        for (MethodOrMethodContext piece : addSet){
            SootMethod method = piece.method();
            Stmt stmt = (Stmt) piece.context();

            assert stmt.containsInvokeExpr();
            Value url = stmt.getInvokeExpr().getArg(0);

            resSet.add(new TrackModel(method,stmt, url));

        }

        return resSet;

    }

    /**TODO
     * $r1 = virtualinvoke r2.<java.net.URL: java.net.URLConnection openConnection()>();
     * virtualinvoke r3.<java.net.HttpURLConnection: void setRequestProperty(java.lang.String,java.lang.String)>("header", "124");
     * 找到URL openconnection语句
     * @param sm
     * @param unitGraph
     * @param u
     * @param target
     * @param targetInvokeSig
     * @return
     */
    private Set<TrackModel> getTargetInvokeBase(SootMethod sm, ExceptionalUnitGraph unitGraph, Unit u, Value target){
        Set<TrackModel> result = new HashSet<>();
        if (!sm.hasActiveBody())
            return result;

        if (unitGraph == null){
            unitGraph = new ExceptionalUnitGraph(sm.retrieveActiveBody());
        }

        LocalDefs localDefs = new SimpleLocalDefs(unitGraph);
        List<Unit> defUnits = localDefs.getDefsOfAt((Local) target, u);

        for (Unit defUnit : defUnits){
            DefinitionStmt defStmt = (DefinitionStmt) defUnit;

            Value rightOp = defStmt.getRightOp();

            if (rightOp instanceof ParameterRef){
                ParameterRef ref = (ParameterRef) rightOp;
                int index = ref.getIndex();

                Iterator<Edge> ite = cg.edgesInto(sm);
                while (ite.hasNext()){
                    Edge edge = ite.next();
                    SootMethod caller = edge.src();
                    Unit callingUnit = edge.srcUnit();
                    Value arg = edge.srcStmt().getInvokeExpr().getArg(index);

                    result.addAll(getTargetInvokeBase(caller, null, callingUnit, arg));
                }
            }

            else if(rightOp instanceof FieldRef){
                Set<TrackModel> fieldsDefs = getFieldsTrack(((FieldRef) rightOp).getField());
                for (TrackModel defs : fieldsDefs){
                    result.addAll(getTargetInvokeBase(defs.getLocateMethod(), defs.getUnitGraph(), defs.getLocateUnit(), defs.getTargetValue()));
                }
            }

            else if (rightOp instanceof Local){
                result.addAll(getTargetInvokeBase(sm, unitGraph, defUnit, rightOp));
            }

            else if (rightOp instanceof CastExpr){
                result.addAll(getTargetInvokeBase(sm, unitGraph, defUnit, ((CastExpr) rightOp).getOp()));
            }

            else if (rightOp instanceof InvokeExpr){
                InvokeExpr ie = (InvokeExpr) rightOp;
                SootMethod invokeMeth = ie.getMethod();

                if (invokeMeth.getSignature().equals("<java.net.URL: java.net.URLConnection openConnection(java.net.Proxy)>")
                        || invokeMeth.getSignature().equals("<java.net.URL: java.net.URLConnection openConnection()>")){
                    assert ie instanceof InstanceInvokeExpr;
                    result.add(new TrackModel(sm, u, ((InstanceInvokeExpr) ie).getBase(), unitGraph, false));
                }

                else if (info.isApplicationClass(invokeMeth.getDeclaringClass())){
                    List<ReturnStmt> returns = getReturnConnection(invokeMeth);
                    if (returns != null){
                        for (ReturnStmt res : returns){
                            if (res.getOp() instanceof Local)
                                result.addAll(getTargetInvokeBase(invokeMeth, null,  res, res.getOp()));
                        }
                    }

                }
            }

            else{
                mLogger.info("Unresolved URLConnection def right type: {}", rightOp);
            }
        }
        return result;
    }



    // specialinvoke r2.<java.net.URL: void <init>(java.lang.String)>("hduhd");
    // $r1 = virtualinvoke r2.<java.net.URL: java.net.URLConnection openConnection()>();
    // virtualinvoke r3.<java.net.HttpURLConnection: void setRequestProperty(java.lang.String,java.lang.String)>("header", "124");
    private Set<MethodOrMethodContext> getTargetInitUrl(SootMethod sm, Unit u, Value con, String targetInvokeSig){
        Set<MethodOrMethodContext> set = new HashSet<>();

        if (!sm.hasActiveBody() || con instanceof NullConstant){
            return set;
        }

        UnitGraph unitGraph = new BriefUnitGraph(sm.getActiveBody());
        LocalDefs localDefs = new SimpleLocalDefs(unitGraph);

        List<Unit> defUnits = localDefs.getDefsOfAt((Local) con, u);

        for (Unit defUnit : defUnits){
            assert defUnit instanceof DefinitionStmt;
            Value rightOp = ((DefinitionStmt) defUnit).getRightOp();

            // 1. HttpURLConnection 是传入的arg
            if (rightOp instanceof ParameterRef){
                ParameterRef ref = (ParameterRef) rightOp;
                int index = ref.getIndex();

                Iterator<Edge> ite = cg.edgesInto(sm);
                while (ite.hasNext()){
                    Edge edge = ite.next();
                    SootMethod caller = edge.src();
                    Unit callingUnit = edge.srcUnit();
                    Value arg = edge.srcStmt().getInvokeExpr().getArg(index);

                    if (!computedCallers.contains(MethodContext.v(caller, callingUnit)))
                        set.addAll(getTargetInitUrl(caller, callingUnit, arg, targetInvokeSig));
                    computedCallers.add(MethodContext.v(caller, callingUnit));
                }
            }

            else if (rightOp instanceof FieldRef){
                SootField conField = ((FieldRef) rightOp).getField();

                for (SootMethod method : conField.getDeclaringClass().getMethods()){
                    if (method.hasActiveBody()){
                        for (Unit uu : method.getActiveBody().getUnits()){
                            if (uu instanceof AssignStmt){
                                Value leftOp = ((AssignStmt) uu).getLeftOp();
                                if (leftOp instanceof FieldRef && ((FieldRef) leftOp).getField().equals(conField)){
                                    Value right = ((AssignStmt) uu).getRightOp();
                                    if (right.getType() instanceof NullType)
                                        continue;

                                    set.addAll(getTargetInitUrl(method, uu, right, targetInvokeSig));

                                }

                            }
                        }
                    }
                }

            }

            else if (rightOp instanceof Local){
                set.addAll(getTargetInitUrl(sm, defUnit, rightOp, targetInvokeSig));
            }
            else if (rightOp instanceof CastExpr){
                Value originOp = ((CastExpr) rightOp).getOp();
                if (!(originOp.getType() instanceof NullType)){
                    set.addAll(getTargetInitUrl(sm, defUnit, ((CastExpr) rightOp).getOp(), targetInvokeSig));
                }

            }

            // 3.invokeie,<java.net.URL: java.net.URLConnection openConnection()>
            else if (rightOp instanceof InvokeExpr) {
                InvokeExpr ie = (InvokeExpr) rightOp;
                SootMethod invokeMeth = ie.getMethod();


                boolean temp = false;
                if (targetInvokeSig.equals(URL_OPEN_CONNECTION_METH_SIG)){
                    temp = invokeMeth.getSignature().equals("<java.net.URL: java.net.URLConnection openConnection(java.net.Proxy)>")
                            || invokeMeth.getSignature().equals("<java.net.URL: java.net.URLConnection openConnection()>");
                }
                else if (targetInvokeSig.equals(URI_TO_URL_SIG))
                    temp = invokeMeth.getSignature().equals("<java.net.URI: java.net.URL toURL()>");


                if (temp/*invokeMeth.getSignature().equals(targetInvokeSig)*/){
                    assert ie instanceof InstanceInvokeExpr;
                    set.addAll(findUrlInit(sm, defUnit, ((InstanceInvokeExpr) ie).getBase()));
                }

                // callee返回的httpurlconnection
                else if (info.isApplicationClass(invokeMeth.getDeclaringClass())){
                    if (!computedCallees.contains(invokeMeth)){
                        computedCallees.add(invokeMeth);
                        List<ReturnStmt> returns = getReturnConnection(invokeMeth);
                        if (returns != null){
                            for (ReturnStmt res : returns){
                                if (res.getOp() instanceof Local){
                                    set.addAll(getTargetInitUrl(invokeMeth, res, res.getOp(), targetInvokeSig));
                                }

                            }
                        }
                    }
                }
            }


            else {
                mLogger.info("Unresolved rightOp type: {}", rightOp);
            }

        }
        return set;

    }

    private List<ReturnStmt> getReturnConnection(SootMethod callee){
        if (!callee.hasActiveBody()){
            return null;
        }
        List<ReturnStmt> list = new ArrayList<>();
        for (Unit unit : callee.getActiveBody().getUnits()){
            if (unit instanceof ReturnStmt){
                list.add((ReturnStmt) unit);
            }
        }
        return list;
    }

    /**TODO
     * 从openconnection()语句 获取到<java.net.URL: void <init>(java.lang.String)>($r2)，$r2就是String类型的url
     * @param meth
     * @param unitGraph
     * @param openConUnit
     * @param url
     * @return
     */
    private Set<TrackModel> findUrlInitStr(SootMethod sm, ExceptionalUnitGraph unitGraph, Unit openConUnit, Value url){
        Set<TrackModel> result = new HashSet<>();
        if (!sm.hasActiveBody()){
            return result;
        }

        if (unitGraph == null){
            unitGraph = new ExceptionalUnitGraph(sm.retrieveActiveBody());
        }

        LocalDefs localDefs = new SimpleLocalDefs(unitGraph);
        List<Unit> defUnits = localDefs.getDefsOfAt((Local) url, openConUnit);

        for (Unit defUnit : defUnits){
            DefinitionStmt defStmt = (DefinitionStmt) defUnit;

            Value rightOp = defStmt.getRightOp();

            if (rightOp instanceof ParameterRef){
                ParameterRef ref = (ParameterRef) rightOp;
                int index = ref.getIndex();

                Iterator<Edge> ite = cg.edgesInto(sm);
                while (ite.hasNext()){
                    Edge edge = ite.next();
                    SootMethod caller = edge.src();
                    Unit callingUnit = edge.srcUnit();
                    Value arg = edge.srcStmt().getInvokeExpr().getArg(index);

                    result.addAll(findUrlInitStr(caller, null, callingUnit, arg));
                }
            }

            else if (rightOp instanceof NewExpr){
                LocalUses uses = new SimpleLocalUses(unitGraph, localDefs);
                for (UnitValueBoxPair unitValueBoxPair : uses.getUsesOf(defUnit)) {
                    Unit useUnit = unitValueBoxPair.getUnit();
                    Stmt useStmt = (Stmt) useUnit;

                    if (useStmt.containsInvokeExpr()) {
                        if (useStmt.getInvokeExpr().getMethod().getSignature().equals(URL_INIT_METH_SIG)) {
                            result.add(new TrackModel(sm, defUnit, defStmt.getInvokeExpr().getArg(0)));// TODO ?
                        }
                    }

                }
            }
            else if(rightOp instanceof FieldRef){
                Set<TrackModel> fieldsDefs = getFieldsTrack(((FieldRef) rightOp).getField());
                for (TrackModel defs : fieldsDefs){
                    result.addAll(findUrlInitStr(defs.getLocateMethod(), defs.getUnitGraph(), defs.getLocateUnit(), defs.getTargetValue()));
                }
            }

            else if (rightOp instanceof Local){
                result.addAll(findUrlInitStr(sm, unitGraph, defUnit, rightOp));
            }

            else if (rightOp instanceof CastExpr){
                result.addAll(findUrlInitStr(sm, unitGraph, defUnit, ((CastExpr) rightOp).getOp()));
            }

            else if (rightOp instanceof InvokeExpr){
                InvokeExpr ie = (InvokeExpr) rightOp;
                SootMethod invokeMeth = ie.getMethod();

                if (invokeMeth.getSignature().equals("<java.net.URI: java.net.URL toURL()>")){
                    assert ie instanceof InstanceInvokeExpr;
                    result.add(new TrackModel(sm, openConUnit, ((InstanceInvokeExpr) ie).getBase(), unitGraph, false));// TODO  ??
                }

                else if (info.isApplicationClass(invokeMeth.getDeclaringClass())){
                    List<ReturnStmt> returns = getReturnConnection(invokeMeth);
                    if (returns != null){
                        for (ReturnStmt res : returns){
                            if (res.getOp() instanceof Local)
                                result.addAll(findUrlInitStr(invokeMeth, null,  res, res.getOp()));
                        }
                    }

                }
            }

            else{
                mLogger.info("Unresolved URL def right type: {}", rightOp);
            }
        }
        return result;

    }

    /**
     * 从openconnection()语句 获取到<java.net.URL: void <init>(java.lang.String)>($r2)，$r2就是String类型的url
     * @param meth
     * @param openConUnit
     * @param url
     * @return
     */
    private Set<MethodOrMethodContext> findUrlInit(SootMethod meth, Unit openConUnit, Value url){
        Set<MethodOrMethodContext> set = new HashSet<>();
        if (!meth.hasActiveBody() || url.getType() instanceof NullType){
            return set;
        }

        UnitGraph unitGraph = new BriefUnitGraph(meth.getActiveBody());
        LocalDefs localDefs = new SimpleLocalDefs(unitGraph);

        // 找到
        List<Unit> defUnits = localDefs.getDefsOfAt((Local) url, openConUnit);
        for (Unit def : defUnits){
            Stmt defStmt = (Stmt) def;
            if (defStmt instanceof AssignStmt){
                Value rightOp = ((AssignStmt) defStmt).getRightOp();

                // $r3 = new java.net.URL;
                // specialinvoke $r3.<java.net.URL: void <init>(java.lang.String)>($r2);
                // $r1 = virtualinvoke $r3.<java.net.URL: java.net.URLConnection openConnection()>();
                if (rightOp instanceof NewExpr){
                    LocalUses uses = new SimpleLocalUses(unitGraph, localDefs);
                    for (UnitValueBoxPair unitValueBoxPair : uses.getUsesOf(def)) {
                        Unit useUnit = unitValueBoxPair.getUnit();
                        Stmt useStmt = (Stmt) useUnit;

                        if (useStmt.containsInvokeExpr()) {
                            if (useStmt.getInvokeExpr().getMethod().getSignature().equals(URL_INIT_METH_SIG)) {
                                set.add(MethodContext.v(meth, useStmt));
                            }
                        }

                    }
                }

                else if (rightOp instanceof FieldRef){
                    Set<TrackModel> fieldsDefs = getFieldsTrack(((FieldRef) rightOp).getField());
                    for (TrackModel defField : fieldsDefs){
                        if (computedFields.contains(defField))
                            continue;
                        computedFields.add(defField);
                        set.addAll(findUrlInit(defField.getLocateMethod(), defField.getLocateUnit(), defField.getTargetValue()));
                    }
                }
                else if (rightOp instanceof Local){
                    TrackModel localModel = new TrackModel(meth, defStmt, rightOp);
                    if (!computedFields.contains(localModel)) {
                        computedFields.add(localModel);
                        set.addAll(findUrlInit(meth, defStmt, rightOp));
                    }
                }

                else if (rightOp instanceof InvokeExpr){
                    if (((InvokeExpr) rightOp).getMethod().getSignature().equals(URI_TO_URL_SIG)){
                        assert rightOp instanceof InstanceInvokeExpr;
                        set.addAll(getTargetInitUrl(meth, defStmt, ((InstanceInvokeExpr) rightOp).getBase(), URI_TO_URL_SIG));
                    }

                    else {
                        SootMethod invokeMethod = ((InvokeExpr) rightOp).getMethod();
                        UnitValueBoxPair returnPair;

                        returnPair = getReturnObject(invokeMethod);
                        if (returnPair != null)
                            set.addAll(findUrlInit(invokeMethod, returnPair.getUnit(), returnPair.getValueBox().getValue()));

                    }

                }

                else {
                    mLogger.info("Unresolved URL assign : {}", rightOp);
                }
            }

            // URL 是传入的参数
            else if (defStmt instanceof IdentityStmt){
                ParameterRef parameterRef = (ParameterRef) ((IdentityStmt) defStmt).getRightOp();
                int index = parameterRef.getIndex();

                Iterator<Edge> ite = cg.edgesInto(meth);
                while (ite.hasNext()){
                    Edge edge = ite.next();
                    SootMethod caller = edge.src();
                    Unit callingUnit = edge.srcUnit();
                    Stmt callingStmt = (Stmt) callingUnit;

                    if (!computedCallers.contains(MethodContext.v(caller, callingStmt))){
                        Value arg = callingStmt.getInvokeExpr().getArg(index);
                        if (arg instanceof Local)
                            computedCallers.add(MethodContext.v(caller, callingStmt));
                            set.addAll(findUrlInit(caller, callingUnit, arg));
                    }
                }
            }

        }
        return set;
    }



    private Set<TrackModel> getFieldsTrack(SootField field){
        Set<TrackModel> fieldTracks = new HashSet<>();

        for (SootClass sc : Scene.v().getClasses()){
            if ((!field.isPublic()) && (!sc.getName().startsWith(getOuterClassSig(field.getDeclaringClass())))){
                continue;
            }
            fieldTracks.addAll(scanFieldDefInClass(sc, field));
        }

        return fieldTracks;
    }
    private String getOuterClassSig(SootClass sc){
        while(sc.hasOuterClass()){
            sc = sc.getOuterClass();
        }
        return sc.getName();
    }
    private Set<TrackModel> scanFieldDefInClass(SootClass sc, SootField target){
        Set<TrackModel> result = new HashSet<>();

        for (SootMethod sm : sc.getMethods()){
            if (sm.hasActiveBody()){
                for(Unit u : sm.retrieveActiveBody().getUnits()){
                    Stmt s = (Stmt) u;
                    if (s instanceof AssignStmt){
                        Value leftOp = ((AssignStmt) s).getLeftOp();

                        if (leftOp instanceof FieldRef){
                            SootField field = ((FieldRef) leftOp).getField();

                            if (field.equals(target)){
                                Value rightOp = ((AssignStmt) s).getRightOp();


                                if (!(rightOp.getType() instanceof NullType)) {
                                    if (StringConstant.class.isAssignableFrom(rightOp.getClass()) && ((StringConstant) rightOp).value.isEmpty()){
                                        continue;
                                    }
                                    result.add(new TrackModel(sm, u, rightOp));
                                }
                            }

                        }
                    }
                }
            }
        }

        return result;
    }

    private UnitValueBoxPair getReturnObject(SootMethod meth){
        if (!meth.hasActiveBody())
            return null;
        for (Unit unit : meth.retrieveActiveBody().getUnits()){
            Stmt stmt = (Stmt) unit;

            if (stmt instanceof ReturnStmt){
                Value op = ((ReturnStmt) stmt).getOp();

                if (!(op.getType() instanceof NullType))
                    return new UnitValueBoxPair(unit, ((ReturnStmt) stmt).getOpBox());
            }
        }

        return null;
    }
}
