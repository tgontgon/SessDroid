package analysis.defTrack;


import com.sun.org.apache.bcel.internal.classfile.ConstantString;
import com.sun.xml.internal.ws.policy.EffectiveAlternativeSelector;
import configs.AppInfoConfig;
import models.*;
import models.result.DefTrackInfo;
import models.result.DefTrackResult;
import models.track.TrackModel;
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
import sun.security.pkcs11.wrapper.Constants;
import utils.SessCallGraphBuilder;
import utils.SessDroidLogger;

import java.util.*;

/**
 * 对于一个初始的TrackModel 进行def track
 * 一个初始的trackmodel 对应一个
 * 一个backwardsanalysis 对应一个DefTrackResult，
 */
public class BackwardsTrackAnalysis {
    private AppInfoConfig appConfig;
    private Logger mLogger;
    private DefTrackResult results;
    private CallGraph callGraph;
    private TrackModel startPoint;
    private boolean isFirAnti;
    private List<Value> lastArgs;
    private SootMethod lastCallee;
    private SharedPreModel preModel;
    private DefTrackInfo trackInfo;
    private Set<TrackModel> computedLocal;
    private int trackDepth = 0;
    private Set<SootMethod> wrapperJsonMeths;

    public BackwardsTrackAnalysis(TrackModel input, AppInfoConfig appConfig, DefTrackInfo trackInfo, Set<SootMethod> wrapperJsonMeths){
        this(input, appConfig, Scene.v().getCallGraph(), trackInfo, wrapperJsonMeths);
    }

    public BackwardsTrackAnalysis(TrackModel input, AppInfoConfig appConfig, CallGraph callGraph, DefTrackInfo trackInfo, Set<SootMethod> wrapperJsonMeths){
        this.startPoint = input;
        this.results = new DefTrackResult(startPoint);
        this.mLogger = LoggerFactory.getLogger("Track Analysis");
        this.appConfig = appConfig;
        this.callGraph = appConfig.getCallGraph();
        this.isFirAnti = false;
        this.callGraph = callGraph;
        this.lastArgs = new ArrayList<>();
        this.lastCallee = null;
        this.preModel = new SharedPreModel();
        this.trackInfo = trackInfo;
        this.computedLocal = new HashSet<>();
        this.wrapperJsonMeths = wrapperJsonMeths;
    }

    /**
     * offer the main function interface to out
     */
    public void trackAnalysis(){
        if (isConstantDefStr(startPoint)){
            isFirAnti = true;
            SessDroidLogger.Info("Find Client-generated Token Defect. " + startPoint);
            VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.CLIENT_GENERATED_TOKEN, appConfig.getApkName());
        }

        trackInfo.addDefTrackResult(results);

    }


    /**
     *
     * Main function in def track analysis
     *
     * @param model
     * @return
     */
    private boolean isConstantDefStr(TrackModel model){
        trackDepth++;
        Value token = model.getTargetValue();
        SootMethod sm = model.getLocateMethod();
        Unit u = model.getLocateUnit();
        ExceptionalUnitGraph unitGraph = model.getUnitGraph();


        if (token instanceof StringConstant){
            if (((StringConstant) token).value.equals("Basic")){
                return false;
            }
            return true;

        }

        else if (token instanceof Local){
            computedLocal.add(model);

            SimpleLocalDefs localDefs = new SimpleLocalDefs(unitGraph);

            List<Unit> defs = localDefs.getDefsOfAt((Local) token, u);
            boolean tempAnti = false;

            //对于每一种不同的定义，只要有一种定义路线返回的是true，那么反模式成立
            //但为了后续expiration的检验，需要全部走完backward路线
            for (Unit def : defs){

                if (def instanceof IdentityStmt){
                    tempAnti = doIdentityAnalysis((IdentityStmt) def, sm) || tempAnti;
                }
                else if (def instanceof AssignStmt){
                    tempAnti = doAssignAnalysis(unitGraph, sm, (AssignStmt) def) || tempAnti;
                }

            }
            return tempAnti;
        }

        else
            return false;

    }

    /**
     * def unit is identifyStmt
     * call graph
     * @return
     */
    private boolean doIdentityAnalysis(IdentityStmt idStmt, SootMethod currentSm){
        if (results.getTrackedCallee().contains(currentSm.getSignature()))
            return false;
        results.addTrackedCallee(currentSm.getSignature());

        if (!(idStmt.getRightOp() instanceof ParameterRef)){
            return false;
        }
        ParameterRef pRef = (ParameterRef) idStmt.getRightOp();
        int index = pRef.getIndex();

        Set<TrackModel> callers = getCallersModel(currentSm, index);

        if (callers.isEmpty()){
            if (currentSm.getDeclaringClass().hasOuterClass()){
                mLogger.info("Token comes from callback method: {} return index: {} ", currentSm.getSignature(), index);
                return false;
            }
        }

        boolean temp = false;
        for (TrackModel model : callers){
            temp = isConstantDefStr(model) || temp;
        }
        return temp;
    }

    private Set<TrackModel> getCallersModel(SootMethod callee, int argIndex){
        Set<TrackModel> callers = new HashSet<>();

        Iterator<Edge> edgeIter =  callGraph.edgesInto(callee);
        while(edgeIter.hasNext()){
            Edge edge = edgeIter.next();
            SootMethod caller = edge.src();
            Unit callingUnit = edge.srcUnit();

            Stmt stmt = (Stmt) callingUnit;
            assert stmt.containsInvokeExpr();
            Value token = stmt.getInvokeExpr().getArg(argIndex);


            if (token instanceof NullConstant || (token instanceof StringConstant && ((StringConstant) token).value.isEmpty()))
                continue;

            callers.add(new TrackModel(caller, stmt, token, false));
        }

        return callers;
    }



    private boolean doAssignAnalysis(ExceptionalUnitGraph unitGraph, SootMethod currentSm, AssignStmt asStmt){
        Value right = asStmt.getRightOp();
        if (right instanceof NullConstant)
            return false;

        /*if (right instanceof InvokeExpr){
            SootMethod invokeMeth = ((InvokeExpr) right).getMethod();

            if(isLibraryMethod(invokeMeth)){
                if (invokeMeth.getSignature().equals("<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>")){
                    boolean temp = false;
                    for (TrackModel spTrack : getSpPutCallerPairs(currentSm, unitGraph, asStmt,((InvokeExpr) right).getArg(0))){
                        temp = temp || isConstantDefStr(unitGraph, spTrack);
                    }
                    return temp;
                }

                else if (invokeMeth.getSignature().equals("<java.net.URLConnection: java.lang.String getHeaderField(java.lang.String)>")){
                    //
                    mLogger.debug("Unresolved URLConnection.getHeaderField() in {}" ,currentSm);
                }

                else{

                    LibraryStringHandler libraryMethHandler = new LibraryStringHandler(unitGraph, asStmt, (InvokeExpr) right);
                    if (libraryMethHandler.isFixed()){
                        return true;
                    }
                    else if (!libraryMethHandler.getTrackPairs().isEmpty()){
                        boolean tempAnti = true;
                        for (TrackModel nexTrack : libraryMethHandler.getTrackPairs()){
                            if (nexTrack.getTargetValue().getType().toString().equals("java.lang.String")){
                                tempAnti = tempAnti && isConstantDefStr(unitGraph, nexTrack);
                            }
                            else{
                                //TODO object tracking
                            }
                        }
                        return tempAnti;
                    }
                }
                //else 未处理的已经logger输出

            }

            else{

                if (right instanceof StaticInvokeExpr){
                }

                else if (right instanceof InstanceInvokeExpr){
                    //TODO 特定base的方法
                }
                else{
                    mLogger.debug("Unresolved assign invokeExpr: {}({}) in {}", right, right.getClass(), currentSm);
                }
            }

        }*/
        else if (right instanceof InvokeExpr){

            SootMethod callee = ((InvokeExpr) right).getMethod();

            if (!results.getTrackedInvokes().contains(callee.getSignature())) {

                // 1. get from json object.
                if (wrapperJsonMeths.contains(callee)){
                    return false;
                }

                // 2. library method
                else if (isLibraryMethod(callee)){

                    if (callee.getSignature().equals("<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>")){

                        if (currentSm.getSignature().equals("<io.woebot.service.TokenManager: java.lang.String getTokenFromSharedPrefs(android.content.Context,java.lang.String)>")){
                            SootMethod sootMethod = Scene.v().getMethod("<io.woebot.service.TokenManager: void saveTokensToPrefs(android.content.Context,java.lang.String,java.lang.String)>");
                            Iterator<Edge> ite = callGraph.edgesInto(sootMethod);

                            boolean temp = false;
                            while (ite.hasNext()){
                                Edge edge = ite.next();
                                SootMethod caller = edge.src();
                                Stmt callingStmt = edge.srcStmt();

                                InvokeExpr ie =  callingStmt.getInvokeExpr();
                                TrackModel model = new TrackModel(caller, callingStmt, ie.getArg(1));

                                temp = temp || isConstantDefStr(model);
                            }
                            return temp;
                        }


                        Set<TrackModel> tracks = getSpPutCallerPairs(currentSm, unitGraph, asStmt, ((InvokeExpr) right).getArg(0));
                        boolean temp = false;
                        for (TrackModel track : tracks){
                            temp = temp || isConstantDefStr(track);
                        }
                        return temp;
                    }

                    LibraryStringHandler libraryHandler = new LibraryStringHandler(unitGraph, asStmt, (InvokeExpr) right);
                    if (libraryHandler.isFixed()){
                        SessDroidLogger.Info(appConfig.getApkName()+ " set " + callee.getSignature() +" as token." + startPoint.getLocateMethod());
                        return true;
                    }

                    else if (!libraryHandler.getTrackPairs().isEmpty()){
                        Set<TrackModel> tracks = libraryHandler.getTrackPairs();
                        boolean temp = true;
                        for (TrackModel track : tracks){
                            temp = temp && isConstantDefStr(track);
                        }

                        return temp;
                    }

                }

                else {
                    InvokeExpr ie = (InvokeExpr) right;
                    results.addTrackedInvokePiece(callee.getSignature());

                    lastCallee = ((InvokeExpr) right).getMethod();
                    lastArgs = ((InvokeExpr) right).getArgs();


                    if (callee.getDeclaringClass().getName().startsWith("com.android.tools.r8.GeneratedOutlineSupport")) {
                        Iterator<Integer> idxIte = dealWithToolAppend(ie).iterator();
                        boolean flag = false;
                        while (idxIte.hasNext()) {
                            int idx = idxIte.next();
                            flag = flag || isConstantDefStr(new TrackModel(currentSm, asStmt, ie.getArg(idx)));
                        }
                        return flag;
                    }

                    else if (callee.getSignature().equals("<com.facebook.AccessToken: java.lang.String getToken()>")){
                        return false;
                    }

                    else if (callee.getSignature().equals("<b.b.a.a.a: java.lang.String t0(java.lang.String,java.lang.String)>")
                            || callee.getSignature().equals("<j.b.e.c.a: java.lang.String a(java.lang.String,java.lang.String)>")) {
                        TrackModel model1 = new TrackModel(currentSm, asStmt, ie.getArg(0));
                        TrackModel model2 = new TrackModel(currentSm, asStmt, ie.getArg(1));
                        return isConstantDefStr(model1) && isConstantDefStr(model2);
                    }
                    else if (callee.getSignature().equals("<kotlin.jvm.internal.Intrinsics: java.lang.String stringPlus(java.lang.String,java.lang.Object)>")
                            || callee.getSignature().equals("<com.bytedance.retrofit2.client.b: void <init>(java.lang.String,java.lang.String)>")
                            || callee.getSignature().equals("<com.ss.android.common.util.e: void a(java.lang.String,java.lang.String)>")){

                        if (((InvokeExpr) right).getArg(0).getType().toString().equals("java.lang.String")){
                            return isConstantDefStr(new TrackModel(currentSm, asStmt, ie.getArg(0)))
                                    && isConstantDefStr(new TrackModel(currentSm, asStmt, ie.getArg(1)));
                        }
                    }


                    else if (callee.getSignature().equals("<com.nike.shared.features.common.utils.ConfigUtils: java.lang.String getString(com.nike.shared.features.common.ConfigKeys$ConfigString)>")){
                        return false;
                    }

                    else {
                        Set<TrackModel> returnTracks = getReturnTrackModel(callee);

                        boolean temp = false;
                        for (TrackModel track : returnTracks){
                            temp = temp || isConstantDefStr(track);
                        }

                        return temp;
                    }

                }

            }

        }

        else if (right instanceof FieldRef){
            SootField sootField = ((FieldRef) right).getField();
            if (!results.getTrackedFields().contains(sootField)){
                results.addTrackedFieldPiece(sootField);

                Set<TrackModel> fieldsTracks = getFieldsTrack(sootField);

                boolean temp = false;
                for (TrackModel track : fieldsTracks){
                    temp = temp || isConstantDefStr(track);
                }
                return temp;
            }

        }

        else if (right instanceof Local){
            TrackModel newModel = new TrackModel(currentSm, asStmt, right, unitGraph, false);
            if (!computedLocal.contains(newModel)) {
                computedLocal.add(newModel);
                return isConstantDefStr(newModel);
            }

        }

        else if (right instanceof StringConstant){
            return true;
        }


        return false;
    }


    private List<Integer> dealWithToolAppend(InvokeExpr ie){
        List<Integer> strArgs = new ArrayList<>();
        for (int i = 0; i < ie.getArgs().size(); i++){
            if (ie.getArg(i).getType().toString().equals("java.lang.String")){
                strArgs.add(i);
            }
        }
        return strArgs;
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

    private Set<TrackModel> scanFieldDefInClass(SootClass sc, SootField target){
        Set<TrackModel> result = new HashSet<>();

        for (SootMethod sm : sc.getMethods()){
            if (sm.hasActiveBody()){
                for(Unit u : sm.retrieveActiveBody().getUnits()){
                    Stmt s = (Stmt) u;
                    if (s instanceof AssignStmt){
                        Value leftOp = ((AssignStmt) s).getLeftOp();

                        if (leftOp.getType() instanceof NullType)
                            continue;
                        if (leftOp instanceof FieldRef){
                            SootField field = ((FieldRef) leftOp).getField();


                            if (field != null && field.equals(target)){
                                Value rightOp = ((AssignStmt) s).getRightOp();

                                if (filterValue(rightOp))
                                    result.add(new TrackModel(sm, u, rightOp));;
                            }

                        }
                    }
                }
            }
        }

        return result;
    }
    private String getOuterClassSig(SootClass sc){
        while(sc.hasOuterClass()){
            sc = sc.getOuterClass();
        }
        return sc.getName();
    }


    private Set<TrackModel> getReturnTrackModel(SootMethod method){
        Set<TrackModel> res = new HashSet<>();

        if (method.hasActiveBody()){
            for (Unit u : method.retrieveActiveBody().getUnits()){
                if (u instanceof ReturnStmt){
                    Value returnOp = ((ReturnStmt) u).getOp();

                    if (filterValue(returnOp))
                        res.add(new TrackModel(method, u, returnOp));
                }
            }
        }
        return res;
    }


    private Set<TrackModel> getSpPutCallerPairs(SootMethod sm, UnitGraph unitGraph, Unit unit, Value label){
        reloadSharedPreModel(sm, unitGraph, unit,label);

        Set<TrackModel> inputs = new HashSet<>();
        if (results.getTrackedInvokes().contains(preModel.putMethSig)){
            return inputs;
        }
        results.addTrackedInvokePiece(preModel.putMethSig);
        results.addSavedSpPiece(preModel);

        for (SootClass sc : Scene.v().getApplicationClasses()){
            if (appConfig.isApplicationClass(sc)){

                for (SootMethod sootMethod : sc.getMethods()){
                    if (sootMethod.hasActiveBody()){
                        Iterator<Unit> ite = sootMethod.getActiveBody().getUnits().snapshotIterator();

                        while (ite.hasNext()){
                            Stmt stmt = (Stmt) ite.next();
                            if (stmt.containsInvokeExpr()){
                                InvokeExpr ie = stmt.getInvokeExpr();

                                if (ie.getMethodRef().getSignature().equals(preModel.putMethSig)){
                                    //key相同
                                    if (ie.getArg(0).equals(preModel.spLabel)){
                                        Value value = ie.getArg(1);

                                        if (filterValue(value))
                                            inputs.add(new TrackModel(sootMethod, stmt, value));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return inputs;

    }


    private void reloadSharedPreModel(SootMethod method, UnitGraph unitGraph, Unit unit, Value label){
        if (label instanceof StringConstant){
            preModel.spLabel = (StringConstant) label;
        }
        else if (label instanceof Local){
            if (!method.equals(lastCallee)){
                return;
            }

            SimpleLocalDefs localDefs = new SimpleLocalDefs(unitGraph);
            Unit defUnit = getDefinition((Local) label, unit, localDefs);
            Stmt defStmt = (Stmt) defUnit;

            if (defStmt instanceof IdentityStmt){
                ParameterRef parameterRef = (ParameterRef) ((IdentityStmt) defStmt).getRightOp();
                int index = parameterRef.getIndex();

                if (lastArgs.get(index) instanceof StringConstant){
                    //就把该方法视为封装过的prefUtil类,需要找对应的put封装方法
                    try {
                        this.preModel = new SharedPreModel(lastCallee.getSignature(), (StringConstant) lastArgs.get(index), findPutSpWrapper(method, (StringConstant) lastArgs.get(index)).getSignature());
                    }catch (NullPointerException e){
                        mLogger.warn("unresolved getSharedPreModel (put sp method not find): " + method.getSignature());
                    }
                }

                else {
                    mLogger.warn("unresolved getSharedPreModel (need to extend): " + method.getSignature());
                }

            }
            else if (defStmt instanceof AssignStmt){
                mLogger.warn("unresolved label def unit : " + defStmt);
            }

            else {
                mLogger.warn("unresolved sp label def stmt : {}" , defStmt.getClass());
            }
        }
        else {
            mLogger.error("strange key type: " + label.getClass());
        }
    }

    private Stmt getDefinition(Local local, Unit u, SimpleLocalDefs localDefs){
        return SessCallGraphBuilder.getDefinition(local, u, localDefs);
    }


    private SootMethod findPutSpWrapper(SootMethod getMeth, StringConstant label){
        Set<SootClass> scanClasses = getAllInnerClasses(getMeth.getDeclaringClass());

        Iterator<SootClass> ite = scanClasses.iterator();
        while (ite.hasNext()){
            SootClass sc = ite.next();
            for (SootMethod me : sc.getMethods()){
                if (me.hasActiveBody()){
                    for (Unit u : me.getActiveBody().getUnits()){
                        if (u.toString().contains("<android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)>")){
                            UnitGraph unitGraph = new BriefUnitGraph(me.getActiveBody());
                            LocalDefs localDefs = new SimpleLocalDefs(unitGraph);

                            Stmt s = (Stmt) u;

                            if (!s.containsInvokeExpr()){
                                continue;
                            }

                            InvokeExpr ie = s.getInvokeExpr();

                            List<Value> values = ie.getArgs();
                            Value key = ie.getArg(0);

                            for (Value value : values){
                                if (value instanceof StringConstant){
                                    if (value.toString().equals(label.toString())){
                                        return me;
                                    }
                                }

                                else {
                                    Unit defUnit = localDefs.getDefsOfAt((Local) value, u).get(0);
                                    if (!(defUnit instanceof IdentityStmt)){
                                        break;
                                    }

                                    return me;
                                }

                            }


                        }
                    }
                }
            }
        }

        return null;
    }

    private Set<SootClass> getAllInnerClasses(SootClass sc){
        Set<SootClass> res = new HashSet<>();
        for (SootClass sootClass : Scene.v().getClasses()){
            if (sootClass.getName().startsWith(sc.getName())){
                res.add(sootClass);
            }
        }
        return res;
    }

    public DefTrackResult getResults() {
        return results;
    }

    private boolean isLibraryMethod(SootMethod sm){
        return !appConfig.isApplicationClass(sm.getDeclaringClass());
        /*sm.getDeclaringClass().isLibraryClass()
                || sm.getDeclaringClass().getName().startsWith("android.")
                || sm.getDeclaringClass().getName().startsWith("okio.");*/
    }

    private Unit getPredOf(Unit u, UnitGraph cfg){
        List<Unit> pred = cfg.getPredsOf(u);
        if (pred == null || pred.isEmpty()){
            return null;
        }
        else
            return pred.get(0);
    }

    public TrackModel getStartPoint() {
        return startPoint;
    }

    public boolean isFirAnti() {
        return isFirAnti;
    }

    public SharedPreModel getPreModel() {
        return preModel;
    }

    class LibraryStringHandler {
        InvokeExpr ie;
        UnitGraph unitGraph;
        Unit thisUnit;
        SootMethod target;
        Set<TrackModel> trackPairs;
        boolean isFixed;

        //LibraryStringHandler(){}
        LibraryStringHandler(ExceptionalUnitGraph unitGraph, Unit u, InvokeExpr ie){
            this.ie = ie;
            this.thisUnit = u;
            this.unitGraph = unitGraph;
            this.target = ie.getMethod();
            this.trackPairs = new HashSet<>();
            isFixed = false;
            loadTrackStr();

        }

        private void loadTrackStr(){
            String methodSig = target.getSignature();

            if (ie.getArgs().size() == 0 && !(ie instanceof InstanceInvokeExpr)){
                isFixed = true;
                return;
            }

            switch (methodSig){
                case "<java.util.UUID: java.lang.String toString()>":
                    isFixed = true;
                    break;
                case "<java.lang.String: java.lang.String format(java.util.Locale,java.lang.String,java.lang.Object[])>":
                    loadFormatAppends(ie);
                    break;
                case "<java.lang.String: java.lang.String format(java.lang.String,java.lang.Object[])>":
                    if (ie.getArgs().get(1).getType().toString().equals("java.lang.String"))
                        trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), thisUnit, ie.getArg(1)));
                    break;
                case "<android.net.Uri: java.lang.String encode(java.lang.String,java.lang.String)>":
                case "<android.net.Uri: java.lang.String encode(java.lang.String)>":
                    trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), thisUnit, ie.getArg(0)));
                    break;
                /*case "<java.lang.Object: java.lang.String toString()>":
                case "<android.net.Uri$Builder: java.lang.String toString()>":
                case "<android.net.Uri: java.lang.String toString()>":*/
                case "<java.lang.String: java.lang.String trim()>":
                case "<java.lang.String: java.lang.String toString()>":
                case "<java.lang.String: java.lang.String toLowerCase()>":
                case "<java.lang.String: java.lang.String toUpperCase()>":
                case "<java.lang.String: java.lang.String substring(int,int)>":
                case "<java.lang.String: java.lang.String replace(java.lang.CharSequence,java.lang.CharSequence)>":
                case "<java.lang.String: java.lang.String replaceAll(java.lang.String,java.lang.String)>":
                case "<java.lang.String: java.lang.String substring(int)>":
                    trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), thisUnit,((InstanceInvokeExpr)ie).getBase()));
                    break;
                case "<java.lang.String: java.lang.String concat(java.lang.String)>":
                    trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), thisUnit, ((InstanceInvokeExpr)ie).getBase()));
                    trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), thisUnit, ie.getArg(0)));
                    break;

                case "<kotlin.jvm.internal.Intrinsics: java.lang.String stringPlus(java.lang.String,java.lang.Object)>":
                    trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), thisUnit, ie.getArg(0)));
                    if (ie.getArg(1).getType().toString().equals("java.lang.String")){
                        trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(),thisUnit, ie.getArg(1)));
                    }
                    break;
                case "<java.lang.StringBuffer: java.lang.String toString()>":
                    loadAppendValues(thisUnit, true);
                    break;
                case "<java.lang.StringBuilder: java.lang.String toString()>":
                    loadAppendValues(thisUnit, false);
                    break;
                case "<org.json.JSONObject: java.lang.String getString(java.lang.String)>":
                case "<org.json.JSONObject: java.lang.String optString(java.lang.String,java.lang.String)>":
                case "<org.json.JSONObject: java.lang.String optString(java.lang.String)>":
                    mLogger.info("[LSH] Token derives returned JSONObject ({})", ie.getArg(0));
                    break;
                default:
                    break;
            }
        }

        public Set<TrackModel> getTrackPairs() {
            return trackPairs;
        }

        public boolean isFixed() {
            return isFixed;
        }

        private void loadAppendValues(Unit sUnit, boolean isStringBuffer){
            Unit pred = getPredOf(sUnit, unitGraph);
            if (isStringBuffer){
                while(pred != null){
                    if (pred.toString().contains("<java.lang.StringBuffer: void <init>()")
                            && !pred.toString().contains("goto")){
                        break;
                    }
                    else if ((pred.toString().contains("<java.lang.StringBuffer: void <init>")
                            ||pred.toString().contains("<java.lang.StringBuffer: java.lang.StringBuffer append("))
                            && !pred.toString().contains("goto")){
                        Stmt predStmt = (Stmt) pred;
                        InvokeExpr ie = predStmt.getInvokeExpr();

                        Value appendValue = ie.getArg(0);
                        if (filterValue(appendValue))
                            trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), pred, appendValue));

                        if (pred.toString().contains("<init>")){
                            break;
                        }
                    }

                    pred = getPredOf(pred, unitGraph);
                }
            }
            else{
                while(pred != null){
                    if (pred.toString().contains("<java.lang.StringBuilder: void <init>()")
                            && !pred.toString().contains("goto")){
                        break;
                    }
                    else if ((pred.toString().contains("<java.lang.StringBuilder: void <init>")
                            ||pred.toString().contains("<java.lang.StringBuilder: java.lang.StringBuilder append("))
                            && !pred.toString().contains("goto")){


                        Stmt predStmt = (Stmt) pred;
                        InvokeExpr ie = predStmt.getInvokeExpr();

                        Value appendValue = ie.getArg(0);


                        if (appendValue.toString().contains("Basic") && trackDepth == 1){
                            trackPairs.clear();
                            break;
                        }

                        if (appendValue instanceof StringConstant && ((StringConstant) appendValue).value.equals("")){
                            continue;
                        }

                        if (filterValue(appendValue))
                            trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), pred, appendValue));

                        if(pred.toString().contains("<init>")){
                            break;
                        }

                    }
                    pred = getPredOf(pred, unitGraph);
                }
            }
        }

        private void loadFormatAppends(InvokeExpr ie){
            Value objects = ie.getArg(2);
            SimpleLocalDefs localDefs = new SimpleLocalDefs(unitGraph);

            assert objects instanceof Local;
            Unit defUnit = getDefinition((Local) objects, thisUnit, localDefs);

            LocalUses localUses = new SimpleLocalUses(unitGraph, localDefs);
            List<UnitValueBoxPair> uses = localUses.getUsesOf(defUnit);

            for (UnitValueBoxPair pair : uses){
                Unit useUnit = pair.getUnit();
                Value useValue = pair.getValueBox().getValue();
                if (useUnit instanceof AssignStmt){
                    Value leftOp = ((AssignStmt) useUnit).getLeftOp();
                    if (leftOp instanceof ArrayRef && ((ArrayRef) leftOp).getBase().equals(useValue)){
                        Value rightOp = ((AssignStmt) useUnit).getRightOp();
                        if (rightOp.getType().toString().equals("java.lang.String")){
                            trackPairs.add(new TrackModel(unitGraph.getBody().getMethod(), useUnit, rightOp));
                        }
                    }
                }

            }
        }


    }
    private boolean filterValue(Value v){
        return !(v.getType() instanceof NullType) && (!(v instanceof StringConstant) || !((StringConstant) v).value.isEmpty());
    }

    public Set<TrackModel> getComputedLocal() {
        return computedLocal;
    }
}
