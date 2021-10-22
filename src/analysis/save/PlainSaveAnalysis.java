package analysis.save;

import configs.AppInfoConfig;
import exceptions.NullSaveInputException;
import exceptions.NullSpecIndexParameterRef;
import models.VulnResults;
import models.track.TrackModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.*;
import utils.SessDroidLogger;

import java.util.*;

public class PlainSaveAnalysis {
    private Set<TrackModel> sourceData;
    private Set<String> tokenGetSource;

    private AppInfoConfig config;
    private HashMap<SootField, Set<Unit>> computedFieldDefPairs;
    private HashSet<SootMethod> computedLocateMeths;

    private static Logger logger = LoggerFactory.getLogger("PlainSaveAnalysis: ");
    private static final String SP_EDITOR_PUT_STRING= "<android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)>";
    private static final String STR_BUILDER_APPEND = "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>";
    private static final String STR_BUFFER_APPEND = "<java.lang.StringBuffer: java.lang.StringBuffer append(java.lang.String)>";
    private static final String STR_BUILDER_TO_STRING = "<java.lang.StringBuilder: java.lang.String toString()>";
    private static final String STR_BUFFER_TO_STRING = "<java.lang.StringBuffer: java.lang.String toString()>";

    public PlainSaveAnalysis(AppInfoConfig config) {
        this.config = config;
        this.computedFieldDefPairs = new HashMap<>();
        this.computedLocateMeths = new HashSet<>();
    }

    public void plainSaveAnalysis(){
        if (sourceData == null){
            throw new NullSaveInputException("PlainSaveAnalysis: Check source data, it has not been initialized.");
        }

        sourceData.addAll(parseGetSource());

        Iterator<TrackModel> ite = sourceData.iterator();

        while (ite.hasNext()){
            TrackModel trackModel = ite.next();
            if (isPlainSave(trackModel)){
                VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.PLAIN_SAVE_TOKEN, config.getAppPackName());
                return;
            }
        }

    }

    private Set<TrackModel> parseGetSource(){
        Set<TrackModel> input = new HashSet<>();
        if (tokenGetSource == null){
            return input;
        }

        for (SootClass sc : Scene.v().getClasses()){
            if (!config.isApplicationClass(sc))
                continue;
            for (SootMethod sm : sc.getMethods()){
                if (!sm.hasActiveBody())
                    continue;
                for (Unit unit : sm.retrieveActiveBody().getUnits()){
                    Stmt stmt = (Stmt) unit;

                    if (stmt.containsInvokeExpr() && stmt instanceof AssignStmt){
                        InvokeExpr ie = stmt.getInvokeExpr();
                        Value leftOp = ((AssignStmt) stmt).getLeftOp();

                        if (leftOp instanceof Local
                                && tokenGetSource.contains(ie.getMethod().getSignature())){
                            input.add(new TrackModel(sm, unit, leftOp));
                        }
                    }
                }
            }
        }
        return input;
    }


    private boolean isPlainSave(TrackModel track) {
        Value token = track.getTargetValue();
        if (!(token instanceof Local)){
            return false;
        }

        SootMethod method = track.getLocateMethod();
        Unit unit = track.getLocateUnit();

        return isPlainSaveInternal(method, (Local) token, unit);
    }


    private boolean isPlainSaveInternal(SootMethod sootMethod, Local token, Unit defUnit) {
        if (computedLocateMeths.contains(sootMethod)){
            return false;
        }
        computedLocateMeths.add(sootMethod);

        UnitGraph unitGraph = new ExceptionalUnitGraph(sootMethod.retrieveActiveBody());
        LocalDefs localDefs = new SimpleLocalDefs(unitGraph);

        SimpleLocalUses localUses = new SimpleLocalUses(unitGraph, localDefs);
        List<UnitValueBoxPair> usePairs = localUses.getUsesOf(defUnit);

        Iterator<UnitValueBoxPair> useIter = usePairs.listIterator();
        while (useIter.hasNext()){
            UnitValueBoxPair use = useIter.next();
            Unit unit = use.getUnit();

            Stmt stmt = (Stmt) unit;

            // TODO 判断unit类型，token是否作为一个参数
            // 1.含有invokeExpr，作为invokeExpr的参数
            //    如果作为某调用的参数，那么进入该方法内部找
            //    其他情况？
            if (stmt.containsInvokeExpr()){

                InvokeExpr ie = stmt.getInvokeExpr();
                SootMethod callee = ie.getMethod();

                // only process the token argument
                if (!ie.getArgs().contains(token)){
                    continue;
                }

                // 1.1 if the token is a parameter of putString(), regard as a defect.
                if (callee.getSignature().equals(SP_EDITOR_PUT_STRING)){
                    SessDroidLogger.Info("Find plain save defect, apk: " + config.getApkName());
                    VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.PLAIN_SAVE_TOKEN, config.getApkName());
                    return true;
                }

                // TODO String append situation
                else if (callee.getSignature().equals(STR_BUILDER_APPEND)){
                    InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;

                    UnitValueBoxPair composedToken = getComposedStr(sootMethod, unit, (Local) iie.getBase(), STR_BUILDER_TO_STRING);
                    if (composedToken != null && isPlainSaveInternal(sootMethod, (Local) composedToken.getValueBox().getValue(), composedToken.getUnit())){
                        return true;
                    }
                }

                else if (callee.getSignature().equals(STR_BUFFER_APPEND)){
                    InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;

                    UnitValueBoxPair composedToken = getComposedStr(sootMethod, unit, (Local) iie.getBase(), STR_BUFFER_TO_STRING);
                    if (composedToken != null && isPlainSaveInternal(sootMethod, (Local) composedToken.getValueBox().getValue(), composedToken.getUnit())){
                        return true;
                    }
                }

                // 1.2 if the token is parameter of a callee, follow the token in callee
                else if (config.isApplicationClass(callee.getDeclaringClass())){
                    int idx = getArgumentIndex(token, ie);
                    UnitValueBoxPair calleeDefPair = getIdentifyUnitFromIdx(callee, idx);

                    if (calleeDefPair != null){
                        Value passToken = calleeDefPair.getValueBox().getValue();

                        if (isPlainSaveInternal(callee, (Local) passToken, calleeDefPair.getUnit())){
                            return true;
                        }
                    }
                }
                // 1.3 library method, ignore
            }

            else if (stmt instanceof DefinitionStmt){
                Value leftOp = ((DefinitionStmt) stmt).getLeftOp();

                if (leftOp instanceof FieldRef){
                    Set<TrackModel> assignFieldSet = getFieldAssign(((FieldRef) leftOp).getField());
                    Iterator<TrackModel> iter = assignFieldSet.iterator();

                    while (iter.hasNext()){
                        TrackModel thisTrack = iter.next();
                        SootMethod locateMeth = thisTrack.getLocateMethod();

                        if (isPlainSaveInternal(locateMeth, (Local) thisTrack.getTargetValue(), thisTrack.getLocateUnit())){
                            return true;
                        }
                    }

                }
            }

        }
        return false;
    }

    private UnitValueBoxPair getComposedStr(SootMethod sm, Unit appendUnit, Local sbBase, String toStringSig){
        if (!sm.hasActiveBody()){
            return null;
        }

        UnitGraph unitgraph = new ExceptionalUnitGraph(sm.retrieveActiveBody());

        SimpleLocalDefs localDefs = new SimpleLocalDefs(unitgraph);
        SimpleLocalUses localUses = new SimpleLocalUses(unitgraph, localDefs);

        Unit defUnit = getDefinition(sbBase, appendUnit, localDefs, sm.getSignature());

        Iterator<UnitValueBoxPair> iter = localUses.getUsesOf(defUnit).listIterator();

        while (iter.hasNext()){
            UnitValueBoxPair pair = iter.next();

            Unit useUnit = pair.getUnit();
            if (useUnit.toString().contains(toStringSig)){
                if (useUnit instanceof AssignStmt){
                    ValueBox sb = ((AssignStmt) useUnit).getLeftOpBox();

                    if (sb.getValue() instanceof Local)
                        return new UnitValueBoxPair(useUnit, sb);
                }
            }
        }
        return null;
    }

    private Set<TrackModel> getFieldAssign(SootField tokenField){
        Set<TrackModel> assignPairs = new HashSet<>();

        for (SootClass sc : Scene.v().getApplicationClasses()){
            if (sc.getName().startsWith(getOuterClassSig(tokenField.getDeclaringClass()))){

                for (SootMethod sm : sc.getMethods()){
                    if (!sm.hasActiveBody())
                        continue;
                    for (Unit unit : sm.retrieveActiveBody().getUnits()){
                        Stmt stmt = (Stmt) unit;

                        // update computed Field def units
                        Set<Unit> defUnits = computedFieldDefPairs.getOrDefault(tokenField, new HashSet<>());
                        if (defUnits.contains(unit)){
                            continue;
                        }
                        defUnits.add(unit);
                        computedFieldDefPairs.put(tokenField, defUnits);

                        if (stmt instanceof AssignStmt){
                            Value left = ((AssignStmt) stmt).getLeftOp();
                            Value right = ((AssignStmt) stmt).getRightOp();

                            if (right instanceof FieldRef && ((FieldRef) right).getField().equals(tokenField)){

                                if (left instanceof Local){
                                    assignPairs.add(new TrackModel(sm, unit, ((AssignStmt) stmt).getLeftOp()));
                                }

                            }
                        }
                    }
                }
            }
        }
        return assignPairs;
    }


    private String getOuterClassSig(SootClass sc){
        while(sc.hasOuterClass()){
            sc = sc.getOuterClass();
        }
        return sc.getName();
    }


    private int getArgumentIndex(Local arg, InvokeExpr ie){
        for (int i = 0; i < ie.getArgCount(); i++){
            if (ie.getArg(i).equals(arg)){
                return i;
            }
        }
        return -1;
    }

    private UnitValueBoxPair getIdentifyUnitFromIdx(SootMethod sm, int idx){
        if (!sm.hasActiveBody()){
            return null;
        }

        Body body = sm.retrieveActiveBody();

        for (Unit unit : body.getUnits()){
            if (unit instanceof IdentityStmt){
                IdentityStmt stmt = (IdentityStmt) unit;

                if (stmt.getRightOp() instanceof ParameterRef){
                    ParameterRef parameterRef = (ParameterRef) stmt.getRightOp();
                    if (parameterRef.getIndex() == idx){
                        return new UnitValueBoxPair(stmt, stmt.getLeftOpBox());
                    }
                }
            }

            else break;
        }
        throw new NullSpecIndexParameterRef(String.format("No ParameterRef of index: %d in %s", idx, sm.getSignature()));
    }

    private Unit getDefinition(Local local, Unit u, SimpleLocalDefs localDefs, String methodName){
        List<Unit> defUnits = localDefs.getDefsOfAt(local, u);
        if (defUnits.isEmpty()){
            logger.info("WARM : No definition of the local {} has been found in {}.", local, methodName);
            return null;
        }
        return defUnits.get(0);
    }

    public Set<TrackModel> getSourceData() {
        return sourceData;
    }

    public void setSourceData(Set<TrackModel> sourceData) {
        this.sourceData = sourceData;
    }

    public Set<String> getTokenGetSource() {
        return tokenGetSource;
    }

    public void setTokenGetSource(Set<String> tokenGetSource) {
        this.tokenGetSource = tokenGetSource;
    }
}
