package utils;

import soot.*;
import soot.JastAddJ.BodyDecl;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.ReturnStmt;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class VolleyUtils {

    public final static String VOLLEY_REQUEST_SC_NAME = "com.android.volley.Request";
    /**
     * 判断requestclass是否继承于Volley的Request类
     * @param requestClass
     * @return
     */
    public static boolean isVolleyRequestSubClass(SootClass requestClass) {
        if (requestClass.getName().equals(VOLLEY_REQUEST_SC_NAME)) {
            return true;
        }
        while (requestClass.hasSuperclass()) {
            if (requestClass.getSuperclass().getName().equals(VOLLEY_REQUEST_SC_NAME)) {
                return true;
            }
            requestClass = requestClass.getSuperclass();
        }
        return false;
    }

    public static ValueUnitPair headerWithAuthPair(SootMethod getHeaderMeth){

        Body body = getHeaderMeth.retrieveActiveBody();

        Iterator<ValueUnitPair> ite = getReturnPair(body).iterator();
        while(ite.hasNext()){
            ValueUnitPair pair = ite.next();
            Value returnMap = pair.getValue();

            if (returnMap instanceof Local){
                UnitGraph unitGraph = new ExceptionalUnitGraph(body);
                LocalDefs localDefs = new SimpleLocalDefs(unitGraph);

                List<Unit> defUnits = localDefs.getDefsOfAt((Local) returnMap, pair.getUnit());
                for (Unit defUnit : defUnits){
                    LocalUses uses = new SimpleLocalUses(unitGraph, localDefs);
                    List<UnitValueBoxPair> mapPairs = uses.getUsesOf(defUnit);

                    for (UnitValueBoxPair mapPair : mapPairs){
                        Stmt useStmt = (Stmt) mapPair.getUnit();
                        if (useStmt instanceof InvokeStmt){
                            InvokeExpr ie = useStmt.getInvokeExpr();
                            if (ie.getMethod().getSubSignature().equals("java.lang.Object put(java.lang.Object,java.lang.Object)>")
                                    && SootUtil.isAuthKey(ie.getArg(0).toString())){
                                return new ValueUnitPair(ie.getArg(1), useStmt);
                            }
                        }

                    }
                }
            }
        }
        return null;
    }

    public static List<ValueUnitPair> getReturnPair(Body body){
        List<ValueUnitPair> pairs = new ArrayList<>();

        for (Unit unit :body.getUnits()){
            if (unit instanceof ReturnStmt){
                Value op = ((ReturnStmt) unit).getOp();
                if (!(op instanceof NullType))
                    pairs.add(new ValueUnitPair(op, unit));
            }
        }
        return pairs;
    }

}
