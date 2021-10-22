package analysis.pointsTo;


import configs.AppInfoConfig;
import exceptions.NullDefException;
import models.NewSource;
import models.StringBuilderModel;
import models.VulnResults;
import models.track.TrackModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class LogAnalysis {
    private static String SB_BUILD_TO_STRING_SIG = "<java.lang.StringBuilder: java.lang.String toString()>";
    private static String SB_APPEND_SIG = "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>";
    private static String SB_BUFFER_APPEND_SIG = "<java.lang.StringBuffer: java.lang.StringBuffer append(java.lang.String)>";
    private static String SB_BUFFER_TO_STRING_SIG = "<java.lang.StringBuffer: java.lang.String toString()>";

    private static Logger logger = LoggerFactory.getLogger("Log Analysis: ");
    private TrackModel input;//每一个设置auth请求头的语句创建一个LogAnalysis，作为一个input
    private List<Unit> historyUnits;
    private AppInfoConfig info;
    private Set<SootMethod> wrapperLogSet;

    public LogAnalysis(TrackModel input, AppInfoConfig appInfo, Set<SootMethod> wrapperLogSet){
        this.input = input;
        this.historyUnits = new ArrayList<>();
        this.info = appInfo;
        this.wrapperLogSet = wrapperLogSet;
    }

    public boolean logLeakTrack(){
        if (checkForLog()){
            VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.LEAK_THROUGH_LOG, info.getApkName());
            return true;
        }
        return false;
    }


    /**
     * 追踪 1、check这个local的def语句，如果是tostring，那么append的local们都追踪
     * 2、对def语句找uses
     * 3、如果uses语句是append方法，那么需要获得tostring的对象一起加入check
     * 4、check use语句是否是Log:作为参数的
     * @return
     */
    //先找这个local的def语句 如果是tostring，那么对append的local们都做
    private boolean checkForLog(){
        //在该方法内部往上找，就找该方法
        SootMethod locateMethod = input.getLocateMethod();
        Unit thisUnit = input.getLocateUnit();
        Value token = input.getTargetValue();
        if (token instanceof Constant){
            return false;
        }

        UnitGraph cfg = new ExceptionalUnitGraph(locateMethod.retrieveActiveBody());
        SimpleLocalDefs localDefs = new SimpleLocalDefs(cfg);

        return checkForLogInternal(cfg, localDefs, (Local) token, thisUnit);
    }


    private boolean checkForLogInternal(UnitGraph cfg, SimpleLocalDefs localDefs, Local local, Unit unit){
        ArrayList<Unit> defList = new ArrayList<>();
        collectCandidates(cfg, localDefs, local, unit, defList);
        LocalUses localUses = new SimpleLocalUses(cfg, localDefs);

        List<UnitValueBoxPair> allUses = new ArrayList<>();

        for (Unit defUnit : defList){
            ArrayList<UnitValueBoxPair> temp = new ArrayList<>();
            collectUsesCandidates(cfg, defUnit, localUses, temp, 1);

            allUses.addAll(temp);
        }

        for (UnitValueBoxPair usePair : allUses){
            Stmt stmt = (Stmt) usePair.getUnit();

            if (stmt.containsInvokeExpr()){
                InvokeExpr ie = stmt.getInvokeExpr();
                if (ie.getMethod().getDeclaringClass().getName().startsWith("android.util.Log")
                        || ie.getMethod().getDeclaringClass().getName().startsWith("java.util.logging.Logger")
                        || ie.getMethod().getSignature().equals("<java.io.PrintStream: void println(java.lang.String)>")
                        || ie.getMethod().getSignature().equals("<java.io.PrintStream: void print(java.lang.String)>")
                        || ie.getMethod().getDeclaringClass().getName().startsWith("org.slf4j.Logger")
                        || ie.getMethod().getDeclaringClass().getName().startsWith("org.apache.logging.log4j.Logger")
                        || ie.getMethod().getDeclaringClass().getName().startsWith("timber.log.Timber")
                        || wrapperLogSet.contains(ie.getMethod())){

                    logger.info("Find Log Leak Defect {} in {}", input, cfg.getBody().getMethod().getSignature());
                    return true;
                }
            }

        }

        return false;
    }




    private void collectUsesCandidates(UnitGraph cfg, Unit defUnit, LocalUses localUses, ArrayList<UnitValueBoxPair> temp, int count){
        if (count > 10){
            return;
        }

        List<UnitValueBoxPair> usesList = localUses.getUsesOf(defUnit);
        for (UnitValueBoxPair use : usesList) {
            if (historyUnits.contains(use.getUnit())) {
                continue;
            }
            temp.add(use);

            if (isAppendElement(use)) {
                Stmt stmt = (Stmt) use.getUnit();
                InstanceInvokeExpr iie = (InstanceInvokeExpr) stmt.getInvokeExpr();

                Unit toStringUnit = findUnionStrUnit(cfg, new UnitValueBoxPair(stmt, iie.getBaseBox()));
                collectUsesCandidates(cfg, toStringUnit, localUses, temp, count + 1);
            }

        }
    }

    /**
     *
     * @param pair $r4 = virtualinvoke $r4.<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>($r2);
     * @return $r2 = virtualinvoke $r4.<java.lang.StringBuilder: java.lang.String toString()>();
     */
    private Unit findUnionStrUnit(UnitGraph cfg, UnitValueBoxPair pair){
        Unit curr = pair.getUnit();
        Value sb = pair.getValueBox().getValue();
        while (cfg.getSuccsOf(curr) != null && cfg.getSuccsOf(curr).size() > 0){
            Unit succUnit = cfg.getSuccsOf(curr).get(0);

            if (succUnit.toString().contains(SB_BUILD_TO_STRING_SIG)){
                Stmt succStmt = (Stmt) succUnit;
                InstanceInvokeExpr iie = (InstanceInvokeExpr) succStmt.getInvokeExpr();
                if (iie.getBase().equals(sb)){
                    if (succStmt instanceof AssignStmt){
                        return succUnit;
                    }
                    else {
                        logger.info("Error: toString() unit is not assignStmt.");
                    }
                }
            }
            curr = succUnit;
        }
        return null;
    }

    private boolean isAppendElement(UnitValueBoxPair pair){
        Stmt thisUnit = (Stmt)pair.getUnit();
        if (thisUnit.toString().contains(SB_APPEND_SIG)){
            Value appendValue = thisUnit.getInvokeExpr().getArg(0);
            if (appendValue.equals(pair.getValueBox().getValue())){
                return true;
            }
        }
        else if (thisUnit.toString().contains(SB_BUFFER_APPEND_SIG)){
            logger.info("NEED REPAIR: StringBuffer append arg.");
        }
        return false;
    }

    /**
     * 从addheader那句开始，如果defunit是tostring方法，那么candidate local要加入append的这些local
     * temp先加入自身
     * @param cfg
     * @param localDefs
     * @param local
     * @param unit
     * @param temp
     */
    public void collectCandidates(UnitGraph cfg, SimpleLocalDefs localDefs, Local local, Unit unit, ArrayList<Unit> temp){
        historyUnits.add(unit);

        Unit defUnit = getDefinition(local, unit, localDefs, cfg.getBody().getMethod().getSignature());
        if (defUnit == null){
            return;
        }
        temp.add(defUnit);

        if (defUnit.toString().contains(SB_BUILD_TO_STRING_SIG) || defUnit.toString().contains(SB_BUFFER_TO_STRING_SIG)){
            List<ValueUnitPair> appendList = getAppendLocals(cfg, defUnit);

            for (ValueUnitPair append : appendList){
                Local appendLocal = (Local) append.getValue();
                collectCandidates(cfg, localDefs, appendLocal, append.getUnit(), temp);
            }
        }
    }

    private boolean checkUses(ValueUnitPair pair, LocalUses localUses){
        return false;
    }

    private Unit getDefinition(Local local, Unit u, SimpleLocalDefs localDefs, String methodName){
        List<Unit> defUnits = localDefs.getDefsOfAt(local, u);
        if (defUnits.isEmpty()){
            return null;
        }
        return defUnits.get(0);
    }



    /**
     *
     * @param cfg
     * @param u toString()语句
     * @return
     */
    private List<ValueUnitPair> getAppendLocals(UnitGraph cfg, Unit u){
        if (u.toString().contains(SB_BUILD_TO_STRING_SIG)){
            StringBuilderModel buildModel = new StringBuilderModel();
            List<ValueUnitPair> temp = buildModel.getStringAppendUnits(cfg, u, true);

            return filterAppendLocals(temp);

        }
        else if (u.toString().contains(SB_BUFFER_TO_STRING_SIG)){
            StringBuilderModel bufferModel = new StringBuilderModel();
            List<ValueUnitPair> temp = bufferModel.getStringAppendUnits(cfg, u, false);

            return filterAppendLocals(temp);
        }
        else
            return new ArrayList<>();
    }

    private List<ValueUnitPair> filterAppendLocals(List<ValueUnitPair> origin){
        List<ValueUnitPair> res = new ArrayList<>();

        for (ValueUnitPair pair : origin){
            Value appenArg = pair.getValue();
            if (appenArg instanceof Local){
                res.add(pair);
            }
        }
        return res;
    }
}
