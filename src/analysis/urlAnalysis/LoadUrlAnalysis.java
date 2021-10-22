package analysis.urlAnalysis;

import configs.AppInfoConfig;
import exceptions.NullDefException;
import models.StringBuilderModel;
import models.track.TrackModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JArrayRef;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.toolkits.scalar.ValueUnitPair;
import utils.SootUtil;

import java.util.*;


public class LoadUrlAnalysis {
    private static final Logger log = LoggerFactory.getLogger("LoadUrlAnalysis");
    private final CallGraph callGraph = Scene.v().getCallGraph();
    private List<String> completedMethodSignatures;
    private AppInfoConfig info;
    private boolean isGetFromCallbacks = false;
    private CallGraph callgraph;


    public LoadUrlAnalysis(AppInfoConfig info, CallGraph callGraph){
        this.completedMethodSignatures = new ArrayList<>();
        this.info = info;
    }

    /**
     * 获取url具体内容
     * @return
     */
    public String getLoadUrlStrings(TrackModel input){

        SootMethod sMethod = input.getLocateMethod();
        Unit unit = input.getLocateUnit();
        Value loadUrlArg  = input.getTargetValue();

        if (StringConstant.class.isAssignableFrom(loadUrlArg.getClass())) {
            // It was easy =)
            return ((StringConstant) loadUrlArg).value;
        }

        else {
            // The parameter is a local, and we need to perform a back
            // analysis
            Local loadUrlArgLocal = (Local) loadUrlArg;
            UnitGraph cFlowGraph = new ExceptionalUnitGraph(sMethod.retrieveActiveBody());
            SimpleLocalDefs sLocalDef = new SimpleLocalDefs(cFlowGraph);

            Unit argDefUnit = null;
            try {
                argDefUnit = getDefinition(loadUrlArgLocal, unit, sLocalDef);
            }catch (NullDefException e){
                log.warn(e.getMessage() + unit + sMethod.getSignature());
            }

            if (argDefUnit != null)
                return backTrackAnalysis(sMethod, argDefUnit);
        }

        return "";
    }


    /**
     *
     * @param sMethod:
     *            current method in which we are analysing the reaching defs
     * @param argDefUnit:
     *            unit where the local has been defined
     * @return
     */
    private String backTrackAnalysis(SootMethod sMethod, Unit argDefUnit) {

        if (AssignStmt.class.isAssignableFrom(argDefUnit.getClass())) {
            return assignStmtAnalysis(sMethod, (AssignStmt) argDefUnit);

        } else if (IdentityStmt.class.isAssignableFrom(argDefUnit.getClass())) {

            return identityStmtAnalysis(sMethod, (IdentityStmt) argDefUnit);

        } else {
            // all not supported cases
            log.warn("Unit back track definition not support: {}", argDefUnit.getClass());
            // System.out.println("NOT IMPLEMENTED: "+argDefUnit.getClass());
            return null;
        }

    }

    private String identityStmtAnalysis(SootMethod sMethod, IdentityStmt identityStmt) {

        if(!(identityStmt.getRightOp() instanceof ParameterRef)){
            return "";
        }
        ParameterRef pRef = (ParameterRef) identityStmt.getRightOp();

        int index = pRef.getIndex();
        Set<MethodOrMethodContext> callerInfo = getCallers(sMethod);
        if (callerInfo.isEmpty()){
            // TODO 是回调方法如何判断
            SootClass sClass = sMethod.getDeclaringClass();
            if (sClass.hasOuterClass()
                    && !sMethod.getSignature().equals("<com.acuant.mobilesdk.util.HttpProcessImageConnectRequestTask$1: void a(java.lang.String,int)>")){
                log.error("URL string is come from callbacks in {}, index : {}", sMethod.getSignature(), index);
                isGetFromCallbacks = true;
                return simpleSignature(sMethod);
            }
        }

        return followParameter(index, callerInfo);

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
    private String assignStmtAnalysis(SootMethod sMethod, AssignStmt aStmt) {
        String url = "";

        Value rOpvalue = aStmt.getRightOp();
        if (InvokeExpr.class.isAssignableFrom(rOpvalue.getClass())) {
            InvokeExpr iExpr = (InvokeExpr) rOpvalue;

            SootMethod invokedMethod = iExpr.getMethod();

            if (invokedMethod.getSignature().equals("<java.lang.StringBuilder: java.lang.String toString()>")) {
                UnitGraph cfg = new ExceptionalUnitGraph(sMethod.retrieveActiveBody());
                List<List<Unit>> sBuilderUnits = getStringBuilderUses(cfg, aStmt);

                url = resolveStringBuilder(sMethod, cfg, sBuilderUnits) + url;

            }
            else if (invokedMethod.getSignature().equals("<java.lang.StringBuffer: java.lang.String toString()>")){
                UnitGraph cfg = new ExceptionalUnitGraph(sMethod.retrieveActiveBody());
                List<List<Unit>> sBufferUnits = getStringBuilderUses(cfg, aStmt);
                url = resolveStringBuilder(sMethod, cfg, sBufferUnits) + url;
            }
            // TODO library method
            else if (invokedMethod.getDeclaringClass().isLibraryClass() || invokedMethod.getDeclaringClass().getName().startsWith("androidx.")){

                if (invokedMethod.getSignature().equals("<java.lang.Object: java.lang.String toString()>")
                        || invokedMethod.getSignature().equals("<java.lang.String: java.lang.String trim()>")
                        || invokedMethod.getSignature().equalsIgnoreCase("<java.lang.String: java.lang.String substring(int,int)>")
                        || invokedMethod.getSignature().equalsIgnoreCase("<java.lang.String: java.lang.String substring(int)>")){
                    assert aStmt instanceof InstanceInvokeExpr;
                    Value val = ((InstanceInvokeExpr) aStmt.getInvokeExpr()).getBase();
                    url = resolveObjectString(sMethod, aStmt, val) + url;
                }
                else if (invokedMethod.getSignature().equals("<java.lang.String: java.lang.String valueOf(java.lang.Object)>")){
                    url = resolveObjectString(sMethod, aStmt, aStmt.getInvokeExpr().getArg(0)) + url;
                }

                else if (invokedMethod.getSignature().equals("<java.lang.String: java.lang.String format(java.lang.String,java.lang.Object[])>")){
                    Value val = aStmt.getInvokeExpr().getArg(1);
                    url = resolveObjectString(sMethod, aStmt, val) + url;
                }
                else if (invokedMethod.getSignature().equals("<android.widget.EditText: android.text.Editable getText()>")
                        || invokedMethod.getSignature().equals("<com.google.android.material.textfield.TextInputEditText: android.text.Editable getText()>")
                        || invokedMethod.getSignature().equals("<androidx.appcompat.widget.AppCompatEditText: android.text.Editable getText()>")){
                    isGetFromCallbacks = true;
                    log.error("URL str came from Android EditText without filtering." + sMethod.getSignature());

                    url = simpleSignature(invokedMethod) + url;
                }

                else if (invokedMethod.getSignature().equals("<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>")){
                    Value label = aStmt.getInvokeExpr().getArg(0);
                    if (label instanceof StringConstant){
                        //TODO ctt find sp put invoke
                    }
                }

                else if (invokedMethod.getSignature().equals("<java.lang.String: java.lang.String toLowerCase()>")){
                    Value value = ((InstanceInvokeExpr)aStmt.getInvokeExpr()).getBase();
                    url = resolveObjectString(sMethod, aStmt, value) + url;
                }

            }

            else if (!this.completedMethodSignatures.contains(invokedMethod.getSignature())) {
                url = checkMethod(invokedMethod) + url;
            }
        }

        else if (StringConstant.class.isAssignableFrom(rOpvalue.getClass())) {
            url = ((StringConstant) rOpvalue).value + url;

        }

        else if (FieldRef.class.isAssignableFrom(rOpvalue.getClass())){
            if (!this.completedMethodSignatures.contains(((FieldRef) rOpvalue).getField().getSignature()))
                url = checkField(((FieldRef) rOpvalue).getField()) + url;
        }

        else {
            // all not supported case here
            //InstanceFieldRef iFieldRef = (InstanceFieldRef) rOpvalue;

            if(JArrayRef.class.isAssignableFrom(rOpvalue.getClass())) {
                Iterator<Edge> iter = callGraph.edgesInto(sMethod);
                while(iter.hasNext()) {
                    Edge e = iter.next();
                }

            }
            //return "";

        }

        return url;
    }



    private String simpleSignature(SootMethod sm){
        String[] strs = sm.getDeclaringClass().getName().split("\\.");
        String str = strs[strs.length-1] +"."+ sm.getName() + "()";
        return str;
    }
    private String resolveObjectString(SootMethod contextMethod, Unit sUnit, Value object){

        UnitGraph unitGraph = new ExceptionalUnitGraph(contextMethod.retrieveActiveBody());
        SimpleLocalDefs sLocalDefs = new SimpleLocalDefs(unitGraph);

        Unit defUnit = null;
        try {
            defUnit = getDefinition((Local) object, sUnit, sLocalDefs);
        }catch (NullDefException e){
            log.warn(e.getMessage() + " " + sUnit + " in " + contextMethod.getSignature());
        }

        if (defUnit != null)
            return backTrackAnalysis(contextMethod, defUnit);

        return "";
    }


    private String resolveStringBuilder(SootMethod contextMethod, UnitGraph cfg, List<List<Unit>> sbUnitsLists) {

        StringBuilder resolved = new StringBuilder();

        for (List<Unit> sbUnitList : sbUnitsLists) {
            String current = "";
            for (Unit sBuilderUnit : sbUnitList) {


                if (InvokeStmt.class.isAssignableFrom(sBuilderUnit.getClass())) {
                    InvokeStmt iStmt = (InvokeStmt) sBuilderUnit;
                    SootMethod sMethod = iStmt.getInvokeExpr().getMethod();

                    if (sMethod.getSignature().equals("<java.lang.StringBuilder: void <init>()>")) {
                        resolved.append(current);
                    }

                    else if(sMethod.getSignature().equals("<java.lang.StringBuilder: void <init>(java.lang.String)>")){
                        if(StringConstant.class.isAssignableFrom(iStmt.getInvokeExpr().getArg(0).getClass())) {
                            String sbInitString = ( (StringConstant) iStmt.getInvokeExpr().getArg(0) ).value;
                            current = sbInitString + current;
                        }  else {

                            current = followParameter(0, getCallers(sMethod)) + current;
                        }
                        //TODO: We are ignoring constructor with parameters
                        resolved.append(current);

                    }
                    else {
                        current = computeString(contextMethod, iStmt.getInvokeExpr(), sBuilderUnit, cfg) + current;
                    }

                }

                else if (AssignStmt.class.isAssignableFrom(sBuilderUnit.getClass())) {
                    Value rightOp = ((AssignStmt) sBuilderUnit).getRightOp();

                    if (InvokeExpr.class.isAssignableFrom(rightOp.getClass())) {
                        InvokeExpr iExpr = (InvokeExpr) rightOp;
                        SootMethod sMethod = iExpr.getMethod();

                        if (sMethod.getSignature().equals("<java.lang.StringBuilder: void <init>()>")) {
                            resolved.append(current);
                        }
                        else if (sMethod.getSignature().equals("<java.lang.StringBuilder: void <init>(java.lang.String)>")){

                            if(StringConstant.class.isAssignableFrom(rightOp.getClass())) {
                                String sbInitString = ( (StringConstant) rightOp ).value;
                                current = sbInitString + current;
                            }
                            else {
                                current = followParameter(0, getCallers(sMethod)) + current;
                            }
                            resolved.append(current);
                        }
                        else {
                            current = computeString(contextMethod, iExpr, sBuilderUnit, cfg) + current;
                        }
                    }
                }
                else {
                    // not implemented cases
                    log.warn("String builder unit not supported: {}", sBuilderUnit.getClass());

                }
            }
            resolved.append("|");

        }
        StringBuilder sb = new StringBuilder(resolved.toString());
        if (resolved.length() == 0)
            return sb.toString();
        sb.replace(resolved.length() - 1, resolved.length(), "");
        return sb.toString();
    }


    private String computeString(SootMethod contextMethod, InvokeExpr iExpr, Unit sBuilderUnit, UnitGraph cfg) {

        SootMethod sMethod = iExpr.getMethod();

        if (sMethod.getSignature().equals("<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>") ) {
            Value appendParam = iExpr.getArg(0);

            if (StringConstant.class.isAssignableFrom(appendParam.getClass())) {

                return ((StringConstant) appendParam).value;
            }

            else if (NullConstant.class.isAssignableFrom(appendParam.getClass())){
                return "";
            }

            else {

                Local paramLocal = (Local) appendParam;
                SimpleLocalDefs sLocalDef = new SimpleLocalDefs(cfg);

                Unit backTrackedUnit = null;
                try {
                    backTrackedUnit = getDefinition(paramLocal, sBuilderUnit, sLocalDef);
                }catch (NullDefException e){
                    log.warn(e.getMessage() + " " + sBuilderUnit + " in " + sMethod.getSignature());
                }

                if (backTrackedUnit != null)
                    return backTrackAnalysis(contextMethod, backTrackedUnit);
            }
        }

        return "";
    }

    private String checkField(SootField sField){
        this.completedMethodSignatures.add(sField.getSignature());
        String url = "";

        SootClass sc = sField.getDeclaringClass();
        for (SootMethod sm : sc.getMethods()){
            if (sm.hasActiveBody()){
                for(Unit u : sm.getActiveBody().getUnits()){
                    Stmt s = (Stmt) u;
                    if (AssignStmt.class.isAssignableFrom(s.getClass())){
                        Value leftOp = ((AssignStmt) s).getLeftOp();
                        if (FieldRef.class.isAssignableFrom(leftOp.getClass())
                                && ((FieldRef) leftOp).getField().equals(sField)){

                            Value rightOp = ((AssignStmt) s).getRightOp();

                            if (Local.class.isAssignableFrom(rightOp.getClass())){
                                Local retLocal = (Local) rightOp;
                                UnitGraph cfg = new ExceptionalUnitGraph(sm.getActiveBody());
                                SimpleLocalDefs sLocalDefs = new SimpleLocalDefs(cfg);


                                Unit retDetUnit = null;
                                try {
                                    retDetUnit = getDefinition(retLocal, u, sLocalDefs);
                                }catch (NullDefException e){
                                    log.warn(e.getMessage() + " " + u + " in " + sm.getSignature());
                                }
                                if (retDetUnit != null) {
                                    url = backTrackAnalysis(sm, retDetUnit) + url;
                                }

                            }
                            else if (StringConstant.class.isAssignableFrom(rightOp.getClass())){
                                url = ((StringConstant) rightOp).value + url;
                            }
                        }
                    }
                }
            }
        }
        return url;
    }

    private String checkMethod(SootMethod sMethod) {
        this.completedMethodSignatures.add(sMethod.getSignature());
        String regExprUrl = "";


        for (ValueUnitPair pair : getReturnPair(sMethod)) {
            String url = "";
            ReturnStmt retStmt = (ReturnStmt) pair.getUnit();
            Value retValue = retStmt.getOp();

            if (StringConstant.class.isAssignableFrom(retValue.getClass())) {
                url = ((StringConstant) retValue).value + url;

            }

            else if (Local.class.isAssignableFrom(retValue.getClass())){
                // it is a Local
                Local retlocal = (Local) retValue;
                UnitGraph cfg = new ExceptionalUnitGraph(sMethod.retrieveActiveBody());
                SimpleLocalDefs sLocalDef = new SimpleLocalDefs(cfg);

                Unit retDefUnit = null;

                try {
                    retDefUnit = getDefinition(retlocal, retStmt, sLocalDef);
                }catch (NullDefException e){
                    log.error(e.getMessage() + " " + retStmt + " in " + sMethod.getSignature());
                }

                if (retDefUnit != null){
                    url = backTrackAnalysis(sMethod, retDefUnit) + url;
                }

            }

            regExprUrl += "|"+url;

        }
        StringBuilder sb = new StringBuilder(regExprUrl);
        sb.replace(0, 1, "");
        return sb.toString();
    }

    /**
     *
     * @param callLocates:
     *            edges pointing to method the parameter comes from
     * @param index:
     *            position of parameter to follow
     * @return The Regexp of the string value that the parameter can take
     */
    private String followParameter(int index, Set<MethodOrMethodContext> callLocates){
        List<String> results = new ArrayList<>();

        for (MethodOrMethodContext piece : callLocates){
            String currentResult = "";
            Unit callingUnit = (Unit) piece.context();
            Stmt callingStmt = (Stmt) callingUnit;

            SootMethod callingMethod = piece.method();

            if (completedMethodSignatures.contains(callingMethod.getSignature())){
                continue;
            }

            completedMethodSignatures.add(callingMethod.getSignature());
            Value param = callingStmt.getInvokeExpr().getArg(index);

            if (StringConstant.class.isAssignableFrom(param.getClass())) {

                currentResult = ((StringConstant) param).value;

            } else if (Local.class.isAssignableFrom(param.getClass())){
                // it is a Local

                Local paramLocal = (Local) param;
                UnitGraph cfg = new ExceptionalUnitGraph(callingMethod.retrieveActiveBody());
                SimpleLocalDefs sLocalDef = new SimpleLocalDefs(cfg);

                Unit paramDefUnit = null;

                try {
                    paramDefUnit = getDefinition(paramLocal, callingUnit, sLocalDef);
                }catch (NullDefException e){
                    log.warn(e.getMessage() + " " +callingStmt + " in " + callingMethod.getSignature());
                }

                if (paramDefUnit != null)
                    currentResult = backTrackAnalysis(callingMethod, paramDefUnit);

            }
            if (!currentResult.equals(""))
                results.add(currentResult);

        }

        String regExp = "";

        if (results.size() > 1) {
            regExp = createRegExpr(results);
        } else if (!results.isEmpty()) {
            regExp = results.get(0);
        } else {
            regExp = "*NO RESULT*";
        }

        return regExp;
    }

    /*private String followParameter(int index, Iterator<Edge> edges) {
        List<String> results = new ArrayList<>();

        while (edges.hasNext()) {
            String currentResult = "";
            Edge edge = edges.next();
            Unit callingUnit = edge.srcUnit();
            Stmt callingStmt = edge.srcStmt();

            SootMethod callingMethod = edge.getSrc().method();

            Value param = (Value) callingStmt.getInvokeExpr().getArg(index);
            if (StringConstant.class.isAssignableFrom(param.getClass())) {

                currentResult = ((StringConstant) param).value;

            } else {
                // it is a Local

                Local paramLocal = (Local) param;
                UnitGraph cfg = new ExceptionalUnitGraph(callingMethod.retrieveActiveBody());
                SimpleLocalDefs sLocalDef = new SimpleLocalDefs(cfg);
                Unit paramDefUnit = getDefinition(paramLocal, callingUnit, sLocalDef);

                currentResult = backTrackAnalysis(callingMethod, paramDefUnit);

            }
            if (!currentResult.equals(""))
                results.add(currentResult);

        }

        String regExp = "";

        if (results.size() > 1) {
            regExp = createRegExpr(results);
        } else if (!results.isEmpty()) {
            regExp = results.get(0);
        } else {
            regExp = "*NO RESULT*";
        }

        return regExp;

    }*/

    private String createRegExpr(List<String> strings) {
        StringBuilder sb = new StringBuilder("[");

        if (strings.size() > 1) {
            for (String s : strings) {
                sb.append(s);
                sb.append("|");
            }

            sb.replace(sb.length() - 1, sb.length(), "]");

            return sb.toString();
        } else {
            return "";
        }
    }
    private Set<ValueUnitPair> getReturnPair(SootMethod method){
        Set<ValueUnitPair> res = new HashSet<>();

        if (method.hasActiveBody()){
            for (Unit u : method.retrieveActiveBody().getUnits()){
                if (u instanceof ReturnStmt){
                    Value returnOp = ((ReturnStmt) u).getOp();

                    if (returnOp.getType() instanceof NullType)
                        continue;
                    res.add(new ValueUnitPair(returnOp, u));
                }
            }
        }
        return res;
    }


    private List<List<Unit>> getStringBuilderUses(UnitGraph cfg, Unit sUnit){
        StringBuilderModel sbModel = new StringBuilderModel();
        return sbModel.getStringBuilderUnits(cfg, sUnit);
    }


    /**
     * get unique def unit.
     * @param l
     * @param u
     * @param slocalDef
     * @return
     */
    private Unit getDefinition(Local l, Unit u, SimpleLocalDefs slocalDef) {
        List<Unit> defList = slocalDef.getDefsOfAt(l, u);

        if (defList.size() == 0) {
            throw new NullDefException("No definition of the local has been found");
        }
        return defList.get(0);
    }


    public boolean isGetFromCallbacks() {
        return isGetFromCallbacks;
    }
}
