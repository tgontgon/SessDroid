package analysis.expire;


import configs.AppInfoConfig;
import models.VulnResults;
import models.result.DefTrackInfo;
import models.result.DefTrackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import utils.SessDroidLogger;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ExpireAnalysis {
    private AppInfoConfig info;
    private Logger mLogger;
    private Set<SootField> tokenSigs;
    private Set<String> clickMethods;
    private Set<SootMethod> logoutTrackedMethods;
    private boolean isThirdAnti;
    private DefTrackInfo resultInfo;


    public ExpireAnalysis(AppInfoConfig appInfo, DefTrackInfo trackResult){
        this.info = appInfo;
        this.resultInfo = trackResult;
    }

    public ExpireAnalysis(AppInfoConfig info, Set<SootField> tokenSigs) throws IOException {
        this(info, tokenSigs, dealWithXmlClickMethods(info));
    }
    public ExpireAnalysis(AppInfoConfig info, Set<SootField> tokenSigs, Set<String> clickMeths){
        this.info = info;
        this.tokenSigs = tokenSigs;
        this.clickMethods = clickMeths;
        this.mLogger = LoggerFactory.getLogger("ThirdAnalysis");
        this.logoutTrackedMethods = new HashSet<>();
        this.isThirdAnti = false;
    }

    public boolean isThirdAnti() {
        return isThirdAnti;
    }

    /*public void doLogoutAnalysis(){

        SootMethod meth = getLogoutUIMethod(Collections.singleton(Constants.CLEAR_SP_SIG), 0);

        if (meth == null){
            mLogger.info("Not find the logout ui method!");
            return;
        }
        mLogger.info("the logout ui method is : {}", meth.getSignature());


        for (String tokenSig : tokenSigs){
            if (!isSetNull(meth, tokenSig)){
                mLogger.info("anti pattern3 : {} is not be set null!", tokenSig);
                VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.IMPROPER_EXPIRED_TOKEN, info.getApkName());
            }
        }
    }*/

    public void simpleExpireAnalysis(){
        Set<SootField> NotExpiredSigs = getNotExpiredTokenSigs();
        if (!NotExpiredSigs.isEmpty()){
            isThirdAnti = true;
            SessDroidLogger.Info("Find Not-Expired Token Defect. " + Arrays.deepToString(NotExpiredSigs.toArray()));
            VulnResults.getInstance().addVulnPiece(VulnResults.Vulns.IMPROPER_EXPIRED_TOKEN, info.getApkName());
        }
    }

    private boolean isSpRemoved(){
        //TODO

        return false;
    }

    private Set<SootField> getNotExpiredTokenSigs(){
        Set<SootField> ori = new HashSet<>();

        for (SootField field : tokenSigs){
            if (field.isStatic())
                ori.add(field);
        }

        for (SootClass sc : Scene.v().getApplicationClasses()){
            if (info.isApplicationClass(sc)){
                for (SootMethod sm : sc.getMethods()){
                    if (sm.hasActiveBody()){

                        for (Unit unit : sm.retrieveActiveBody().getUnits()){
                            Stmt stmt = (Stmt) unit;
                            if (stmt instanceof AssignStmt){
                                Value leftOp = ((AssignStmt) stmt).getLeftOp();

                                if (leftOp instanceof FieldRef) {
                                    SootField sf = ((FieldRef) leftOp).getField();
                                    Value rightOp = ((AssignStmt) stmt).getRightOp();

                                    if (ori.contains(sf) && rightOp.getType() instanceof NullType) {
                                        ori.remove(sf);
                                    }
                                    if (ori.contains(sf) && (rightOp instanceof StringConstant && ((StringConstant) rightOp).value.isEmpty())){
                                        ori.remove(sf);
                                    }

                                }

                            }
                        }
                    }

                }
            }
        }
        return ori;
    }


    private SootMethod getLogoutUIMethod(Set<String> traceSigs, int index){

        if (traceSigs.size() == 0){
            return null;
        }
        if (index == 10){
            return null;
        }

        Set<String> nextInputs = new HashSet<>();
        for (String sig : traceSigs){
            Set<SootMethod> sets = backTrackInvokeMeth(sig);
            for (SootMethod sm : sets){
                if (logoutTrackedMethods.contains(sm)){
                    continue;
                }
                logoutTrackedMethods.add(sm);
                if (isClickMethod(sm)) {
                    return sm;
                }
                else{
                    // TODO delete
                    //System.out.println(sm.getSignature());
                    nextInputs.add(sm.getSignature());
                }
            }
        }
        //System.out.println();

        return getLogoutUIMethod(nextInputs,++index);
    }

    /*private SootMethod getLogoutUIMethod(String traceMethSig){

        Set<SootMethod> sets = backTrackInvokeMeth(traceMethSig);
        for (SootMethod sm : sets){
            if (isClickMethod(sm)) {
                return sm;
            }
        }


        Set<SootMethod> result = new HashSet<>();

        while(!sets.isEmpty()){
            for (SootMethod sm : sets){
                if (isClickMethod(sm)){
                    return sm;
                }
                else{
                    result.add(sm);
                    sets.addAll(backTrackInvokeMeth(sm.getSignature()));
                }
            }
        }

        if (!result.isEmpty()){
            return result.iterator().next();
        }
        else
            return null;
    }*/

    private Set<SootMethod> backTrackInvokeMeth(String methSig){
        Set<SootMethod> invokeMeths = new HashSet<>();
        for (SootClass sc : Scene.v().getClasses()){
            if (info.isApplicationClass(sc)){
                for (SootMethod sm : sc.getMethods()){
                    if (sm.hasActiveBody()){
                        for(Unit unit : sm.retrieveActiveBody().getUnits()){
                            Stmt stmt = (Stmt) unit;
                            if (stmt.containsInvokeExpr()){
                                InvokeExpr ie = stmt.getInvokeExpr();
                                SootMethod caller = ie.getMethod();
                                if (caller.getSignature().equals(methSig)){
                                    invokeMeths.add(sm);
                                }
                            }
                        }
                    }
                }
            }
        }
        return invokeMeths;

    }



    public boolean isSetNull(SootMethod logoutMeth, String tokenSig){

        System.out.println(logoutMeth.getSignature());
        if (logoutMeth.hasActiveBody()){
            for (Unit unit : logoutMeth.retrieveActiveBody().getUnits()){
                Stmt stmt = (Stmt) unit;


                if (stmt instanceof AssignStmt){
                    Value leftOp = ((AssignStmt) stmt).getLeftOp();
                    if (leftOp instanceof FieldRef){
                        SootField token = ((FieldRef) leftOp).getField();
                        if (token.getSignature().equals(tokenSig) && ((AssignStmt) stmt).getRightOp().getType() instanceof NullType){
                            mLogger.info("{} sets the token field {} null.", logoutMeth.getSignature(), tokenSig);
                            return true;
                        }
                    }
                }

                else if (stmt instanceof InvokeStmt){
                    InvokeExpr ie = stmt.getInvokeExpr();
                    if (ie.getMethod().equals(logoutMeth) || !info.isApplicationClass(ie.getMethod().getDeclaringClass())){
                        continue;
                    }
                    if (isSetNull(ie.getMethod(), tokenSig))
                        return true;
                }


            }
        }
        return false;
    }


    public boolean isClickMethod(SootMethod invokeMeth){
        if (invokeMeth.getSubSignature().equals("void onClick(android.view.View)")){
            return true;
        }
        if (clickMethods.contains(invokeMeth.getName())){
            return true;
        }
        return false;

        /*for (SootMethod clickMeth : clickMethods){
            if (clickMeth.hasActiveBody()){
                for (Unit unit : clickMeth.getActiveBody().getUnits()){
                    Stmt stmt = (Stmt) unit;
                    if (stmt.containsInvokeExpr()){
                        if (stmt.getInvokeExpr().getMethod().equals(invokeMeth)){
                            return true;
                        }
                    }
                }
            }

        }

        return false;*/

    }
    public static Set<String> dealWithXmlClickMethods(AppInfoConfig apkInfo) throws IOException {
        Set<String> clickMeths = new HashSet<>();
        // 1. 满足实现 android.view.View$OnClickListener 接口，名为onclick的方法
        // 2. 在xml文件里找注册了
        /*for (SootClass sc : Scene.v().getClasses()){
            if (apkInfo.isApplicationClass(sc.toString()) && sc.implementsInterface("android.view.View$OnClickListener")){
                for (SootMethod sm : sc.getMethods()){
                    if (sm.getName().equals("onClick") && sm.hasActiveBody()){
                        clickMeths.add(sm.getSignature());
                    }
                }
            }
        }*/

        ApkLayoutHandler handler = new ApkLayoutHandler(apkInfo.getApkFullPath());
        handler.loadClickMethods();
        clickMeths.addAll(handler.getClickMethods());

        return clickMeths;
    }
}
