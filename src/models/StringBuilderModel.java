package models;

import soot.Unit;
import soot.Value;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ValueUnitPair;

import java.util.ArrayList;
import java.util.List;

public class StringBuilderModel {
    public StringBuilderModel(){
        this.current = new ArrayList<>();
        this.historyUnits = new ArrayList<>();
    }
    private List<Unit> current;
    private List<Unit> historyUnits;


    public List<ValueUnitPair> getStringAppendUnits(UnitGraph cfg, Unit sUnit, boolean isStringBuilder){
        List<ValueUnitPair> results = new ArrayList<>();
        if (historyUnits.contains(sUnit)){
            return results;
        }
        historyUnits.add(sUnit);

        if (isStringBuilder){
            for (Unit pred : cfg.getPredsOf(sUnit)){
                if (pred.toString().contains("<java.lang.StringBuilder: void <init>()")
                        && !pred.toString().contains("goto")){
                    return results;
                }

                else if (pred.toString().contains("<java.lang.StringBuilder: void <init>(java.lang.String)")
                        && !pred.toString().contains("goto")){

                    Stmt predStmt = (Stmt) pred;
                    InvokeExpr ie = predStmt.getInvokeExpr();

                    Value appendValue = ie.getArg(0);
                    results.add(new ValueUnitPair(appendValue, pred));
                    return results;
                }

                else if (pred.toString().contains("<java.lang.StringBuilder: java.lang.StringBuilder append")
                        && !pred.toString().contains("goto")){

                    Stmt predStmt = (Stmt) pred;
                    InvokeExpr ie = predStmt.getInvokeExpr();

                    Value appendValue = ie.getArg(0);
                    results.add(new ValueUnitPair(appendValue, pred));
                    results.addAll(getStringAppendUnits(cfg, pred, true));
                }
                else {
                    results.addAll(getStringAppendUnits(cfg, pred,true));
                }
            }
        }

        else{
            for (Unit pred : cfg.getPredsOf(sUnit)){
                if (pred.toString().contains("<java.lang.StringBuffer: void <init>()")
                        && !pred.toString().contains("goto")){
                    return results;
                }

                else if (pred.toString().contains("<java.lang.StringBuffer: void <init>(java.lang.String)")
                        && !pred.toString().contains("goto")){

                    Stmt predStmt = (Stmt) pred;
                    InvokeExpr ie = predStmt.getInvokeExpr();

                    Value appendValue = ie.getArg(0);
                    results.add(new ValueUnitPair(appendValue, pred));
                    return results;
                }

                else if (pred.toString().contains("<java.lang.StringBuffer: java.lang.StringBuffer append")
                        && !pred.toString().contains("goto")){

                    Stmt predStmt = (Stmt) pred;
                    InvokeExpr ie = predStmt.getInvokeExpr();

                    Value appendValue = ie.getArg(0);
                    results.add(new ValueUnitPair(appendValue, pred));
                    results.addAll(getStringAppendUnits(cfg, pred, false));
                }
                else {
                    results.addAll(getStringAppendUnits(cfg, pred, false));
                }
            }
        }
        return results;

    }

    //TODO: while loop not supported
    public List<List<Unit>> getStringBuilderUnits(UnitGraph cfg, Unit sUnit) {
        List<List<Unit>> results = new ArrayList<>();
        if (historyUnits.contains(sUnit)){
            return results;
        }
        historyUnits.add(sUnit);


        for (Unit pred : cfg.getPredsOf(sUnit)) {

            if (pred.toString().contains("<java.lang.StringBuilder: void <init>")
                    && !pred.toString().contains("goto")) {
                // Base case
                current.add(pred);

                results.add(current);
                current = new ArrayList<>();

            } else if (pred.toString().contains("<java.lang.StringBuilder: java.lang.StringBuilder append")
                    && !pred.toString().contains("goto")) {

                current.add(pred);

                results.addAll(getStringBuilderUnits(cfg, pred));

            } else {
                // We go on
                results.addAll(getStringBuilderUnits(cfg, pred));
            }

        }

        return results;
    }

}
