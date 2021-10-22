package analysis.urlAnalysis.specific;


import configs.AppInfoConfig;
import models.track.TrackModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.tagkit.AnnotationTag;
import soot.tagkit.VisibilityAnnotationTag;
import soot.tagkit.VisibilityParameterAnnotationTag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.*;
import utils.SessCallGraphBuilder;

import java.util.*;

public class OkHttpManager {
    public enum ClientUseType {
        NEW_CALL_AS_BASE("<okhttp3.OkHttpClient: okhttp3.Call newCall(okhttp3.Request)>"),
        RETRO_ADD_CLIENT_AS_ARG("<retrofit2.Retrofit$Builder: retrofit2.Retrofit$Builder client(okhttp3.OkHttpClient)>"),
        PICASSO_OKHTTP3_DOWNLOADER("<com.squareup.picasso.OkHttp3Downloader: void <init>(okhttp3.OkHttpClient)>");

        private final String sig;
        ClientUseType(String s) {
            this.sig = s;
        }

        public String getSig() {
            return sig;
        }
    }

    private String REQUEST_BUILDER_BUILD_SIG = "<okhttp3.Request$Builder: okhttp3.Request build()>";
    private String REQUEST_BUILDER_ADD_URL_SIG = "<okhttp3.Request$Builder: okhttp3.Request$Builder url(java.lang.String)>";
    private String REQUEST_BUILDER_NEW_BUILDER_SIG = "<okhttp3.Request: okhttp3.Request$Builder newBuilder()>";
    private String RETRO_BASE_URL_SIG = "<retrofit2.Retrofit$Builder: retrofit2.Retrofit$Builder baseUrl(java.lang.String)>";
    private String OKHTTP_ADD_INTERCEPTOR_SIG = "<okhttp3.OkHttpClient$Builder: okhttp3.OkHttpClient$Builder addInterceptor(okhttp3.Interceptor)>";
    private String RETRO_BUILDER_BUILD_SIG = "<retrofit2.Retrofit$Builder: retrofit2.Retrofit build()>";
    private String RETRO_BUILDER_INIT_SIG = "<retrofit2.Retrofit$Builder: void <init>";
    private String REQUEST_BUILDER_INIT_SIG = "<okhttp3.Request$Builder: void <init>()>";
    private String CLIENT_BUILDER_BUILD_SIG = "<okhttp3.OkHttpClient$Builder: okhttp3.OkHttpClient build()>";


    private Logger mLogger;
    private AppInfoConfig info;
    private CallGraph mCallGraph;
    private SootClass mInterceptorClass = null;
    private Set<SootClass> retroClasses;
    public boolean isPicassoDLoader;
    private Set<SootMethod> computedCaller;
    private Set<SootField> computedFields;

    public OkHttpManager(AppInfoConfig info, CallGraph cg){
        this.mLogger = LoggerFactory.getLogger("/OkHttpManager");
        this.info = info;
        this.mCallGraph = cg;
        this.retroClasses = new HashSet<>();
        this.isPicassoDLoader = false;
        this.computedCaller = new HashSet<>();
        this.computedFields = new HashSet<>();
    }

    public void showretroclass() {
        for (SootClass sc : retroClasses){
            System.out.println(sc.getName());
        }
    }

    /**
     * 传入找到调用addheader()的位置（TODO postBody中作为内容auth）
     * 返回的是String类型的url为位置
     *
     * @return
     */
    public Set<TrackModel> getOkhttpClientUrls(SootMethod meth, Unit unit, Value requestBuilder){
        Set<TrackModel> resSet = new HashSet<>();
        //Map<SootMethod, Set<ValueUnitPair>> map = new HashMap<>();

        /*SootClass sc = meth.getDeclaringClass();*/

        // 1. addHeader()写在拦截器中
        if (isWrittenIntercept(meth, 1)/*sc.implementsInterface(Constants.OKHTTP_INTERCEPTOR_SC) && meth.getSubSignature().equals(Constants.OKHTTP_INTERCEPTOR_METH_SUB_SIG)*/) {

            Unit urlUnit = null;

            // 1.1 拦截器中有对url的覆盖内容 TODO 精化scanupper和scanlower 因为requestbuilder不太能作用范围大，进行传入传出等操作，所以直接简单的扫描上下句
            if (scanUpperUnit(meth, unit, REQUEST_BUILDER_ADD_URL_SIG, requestBuilder, REQUEST_BUILDER_NEW_BUILDER_SIG) != null){
                urlUnit = scanUpperUnit(meth, unit, REQUEST_BUILDER_ADD_URL_SIG, requestBuilder, REQUEST_BUILDER_NEW_BUILDER_SIG);
            }
            else if (scanLowerUnit(meth, unit, REQUEST_BUILDER_ADD_URL_SIG, requestBuilder, REQUEST_BUILDER_BUILD_SIG) != null){
                urlUnit = scanLowerUnit(meth, unit, REQUEST_BUILDER_ADD_URL_SIG, requestBuilder, REQUEST_BUILDER_BUILD_SIG);
            }

            if (urlUnit != null){
                Stmt urlStmt = (Stmt) urlUnit;
                assert urlStmt.containsInvokeExpr();
                Value url = urlStmt.getInvokeExpr().getArg(0);

                resSet.add(new TrackModel(meth, urlUnit, url));
            }


            // 1.2 拦截器中没有url的覆盖，因此添加该interceptor的client对象taint，将该对对象的newcall中的request在进行分析
            else {
                //获取 $r1(client) = <:build()>处
                Set<TrackModel> clientSet = findClientAddSpecInterceptor(mInterceptorClass);

                for (TrackModel input : clientSet){
                    SootMethod sm = input.getLocateMethod();
                    Unit u = input.getLocateUnit();
                    // 1.寻找该client的newcall处 newcall(request), 往上追溯requestbuilder
                    Set<MethodOrMethodContext> newCalls = findTargetCalls(MethodContext.v(sm, u), ClientUseType.NEW_CALL_AS_BASE);

                    for (MethodOrMethodContext callPieces : newCalls){
                        SootMethod locateMe = callPieces.method();
                        Unit callUn = (Unit) callPieces.context();
                        Stmt callSt = (Stmt) callUn;
                        assert callSt.containsInvokeExpr();
                        Value request = callSt.getInvokeExpr().getArg(0);

                        Set<MethodOrMethodContext> calls = getRequestBuilderUrlCall(locateMe, callUn, request);
                        for (MethodOrMethodContext context : calls) {
                            SootMethod sootMethod = context.method();
                            Stmt urlCall = (Stmt) context.context();

                            assert urlCall.containsInvokeExpr();
                            Value url = urlCall.getInvokeExpr().getArg(0);

                            resSet.add(new TrackModel(sootMethod, urlCall,url ));
                        }

                    }

                    // 2. 对于该client，retro用来添加client，加入base url
                    //  <retrofit2.Retrofit$Builder: retrofit2.Retrofit$Builder client(okhttp3.OkHttpClient)>
                    // 1.2.2 client 作为retrofit的client对象
                    Set<MethodOrMethodContext> retroClients = findTargetCalls(MethodContext.v(sm, u), ClientUseType.RETRO_ADD_CLIENT_AS_ARG);
                    for (MethodOrMethodContext retroPiece : retroClients){

                        // Get the base url retrofit ， 一般正确
                        Stmt uu = (Stmt) retroPiece.context();
                        assert uu.containsInvokeExpr();
                        InvokeExpr ie = uu.getInvokeExpr();
                        if (ie instanceof InstanceInvokeExpr){

                            Value retroBuilder = ((InstanceInvokeExpr) ie).getBase();

                            resSet.addAll(getBaseUrlForRetrofit(new TrackModel(retroPiece.method(), uu, retroBuilder)));
                            /*Unit retroUrl = scanUpperUnit(retroPiece.method(), uu, RETRO_BASE_URL_SIG, retroBuilder, RETRO_BUILDER_INIT_SIG);
                            if (retroUrl == null){
                                retroUrl = scanLowerUnit(retroPiece.method(), uu, RETRO_BASE_URL_SIG,retroBuilder, RETRO_BUILDER_BUILD_SIG);
                            }
                            if (retroUrl != null){
                                Stmt retroStmt = (Stmt) retroUrl;

                                assert retroStmt.containsInvokeExpr();
                                Value url = retroStmt.getInvokeExpr().getArg(0);

                                resSet.add(new TrackModel(retroPiece.method(), retroStmt, url));

                            }*/

                        }

                        // TODO bind the retrofit class -> field
                        bindRetroClass(retroPiece);
                    }

                    Set<MethodOrMethodContext> picassoDownloader = findTargetCalls(MethodContext.v(sm, u), ClientUseType.PICASSO_OKHTTP3_DOWNLOADER);
                    if (picassoDownloader.size() > 0){
                        isPicassoDLoader = true;
                    }

                    // 3. add all the retrofit call class that recover the url (@url)
                    if (!retroClasses.isEmpty()){
                        resSet.addAll(checkAllRetroCalls());
                    }

                }


            }

        }
        //对request直接进行分析
        else {
            Unit urlUnit = scanLowerUnit(meth, unit, REQUEST_BUILDER_ADD_URL_SIG, requestBuilder, REQUEST_BUILDER_BUILD_SIG);
            if (urlUnit == null){
                urlUnit = scanUpperUnit(meth, unit, REQUEST_BUILDER_ADD_URL_SIG, requestBuilder, REQUEST_BUILDER_INIT_SIG);
            }
            if (urlUnit != null){
                Stmt urlStmt = (Stmt) urlUnit;
                assert urlStmt.containsInvokeExpr();
                Value url = urlStmt.getInvokeExpr().getArg(0);

                resSet.add(new TrackModel(meth, urlUnit, url));

            }
        }

        return resSet;
    }

    /**
     * 从retrofit class的接口方法签名和其对应位置的参数，
     */
    private Set<TrackModel> trackUrlParam(SootMethod callee, int urlIndex){
        Set<TrackModel> result = new HashSet<>();

        Set<MethodOrMethodContext> callers = getCallers(callee);
        for (MethodOrMethodContext piece : callers){
            Stmt callingUnit = (Stmt) piece.context();
            Value url = callingUnit.getInvokeExpr().getArg(urlIndex);
            result.add(new TrackModel(piece.method(), callingUnit, url));
        }
        return result;
    }
    /**
     * 检查retrofit class的所有网络请求接口，是否有@
     */
    private Set<TrackModel> checkAllRetroCalls(){
        Set<TrackModel> result = new HashSet<>();

        for (SootClass sc : retroClasses){
            for (SootMethod sm : sc.getMethods()){
                if (!sm.hasTag("VisibilityParameterAnnotationTag")){
                    continue;
                }
                VisibilityParameterAnnotationTag tag = (VisibilityParameterAnnotationTag) sm.getTag("VisibilityParameterAnnotationTag");


                for (int k = 0; k < tag.getVisibilityAnnotations().size(); k++){
                    VisibilityAnnotationTag tt = tag.getVisibilityAnnotations().get(k);
                    if (tt == null || tt.getAnnotations() == null){
                        continue;
                    }
                    for (int i = 0; i < tt.getAnnotations().size(); i++){
                        AnnotationTag annotationTag = tt.getAnnotations().get(i);
                        if (annotationTag.getType().equals("Lretrofit2/http/Url;")){
                            //TODO return value deal
                            result.addAll(trackUrlParam(sm, i));
                        }

                    }
                }

            }
        }
        return result;
    }
    /**
     * 获取request构造时的add url语句
     */
    private Set<MethodOrMethodContext> getRequestBuilderUrlCall(SootMethod meth, Unit unit, Value request){
        Set<MethodOrMethodContext> set = new HashSet<>();

        UnitGraph graph = new BriefUnitGraph(meth.getActiveBody());
        LocalDefs localDefs = new SimpleLocalDefs(graph);

        List<Unit> defUnis = localDefs.getDefsOfAt((Local) request, unit);

        for (Unit defUni : defUnis){
            if (defUni instanceof IdentityStmt){
                ParameterRef parameterRef = (ParameterRef) ((IdentityStmt) defUni).getRightOp();
                int index = parameterRef.getIndex();

                Iterator<Edge> iteEdge = mCallGraph.edgesInto(meth);
                while (iteEdge.hasNext()){
                    Edge edge = iteEdge.next();
                    Stmt callingStmt = edge.srcStmt();
                    SootMethod sm = edge.src();
                    Value secRequest = callingStmt.getInvokeExpr().getArg(index);

                    set.addAll(getRequestBuilderUrlCall(sm, callingStmt, secRequest));
                }

            }

            else if (defUni instanceof AssignStmt){
                Value rightOp = ((AssignStmt) defUni).getRightOp();

                if (rightOp instanceof InvokeExpr){
                    InvokeExpr ie = (InvokeExpr) rightOp;

                    // 1. build
                    if (ie.getMethod().getSignature().equals(REQUEST_BUILDER_BUILD_SIG)){
                        assert ie instanceof InstanceInvokeExpr;
                        Value requestBu = ie.getArg(0);
                        Unit addUrl = scanUpperUnit(meth, unit, REQUEST_BUILDER_ADD_URL_SIG, requestBu, REQUEST_BUILDER_INIT_SIG);

                        if (addUrl != null)
                            set.add(MethodContext.v(meth, addUrl));
                    }

                    // 2. request 通过调用其他方法得到
                    else {
                        List<ReturnStmt> reStmts = getReturnStmt(ie.getMethod());
                        for (ReturnStmt reStmt : reStmts){
                            Value op = reStmt.getOp();
                            if (op instanceof Local){
                                set.addAll(getRequestBuilderUrlCall(ie.getMethod(),reStmt, op));
                            }

                        }

                    }

                }
            }
            else{
                System.out.println("ERROR: Unknown definition unit : " + defUni + "(" + defUni.getClass() + ")" + " in method : " + meth.getSignature());
            }
        }

        return set;

    }


    private Set<MethodOrMethodContext> findTargetCalls(MethodOrMethodContext piece, ClientUseType type){
        Set<MethodOrMethodContext> set = new HashSet<>();

        SootMethod sm = piece.method();
        Unit defUnit = (Unit) piece.context();
        if (!sm.hasActiveBody())
            return set;

        UnitGraph unitGraph = new BriefUnitGraph(sm.getActiveBody());
        LocalDefs localDefs = new SmartLocalDefs(unitGraph, new SimpleLiveLocals(unitGraph));
        LocalUses localUses = new SimpleLocalUses(unitGraph, localDefs);

        List<UnitValueBoxPair> pairs = localUses.getUsesOf(defUnit);
        for (UnitValueBoxPair usePair : pairs){
            Stmt useStmt = (Stmt) usePair.getUnit();
            Value target = usePair.getValueBox().getValue();

            // 1. 目标invokeMethSig或者作为参数传入callee内部
            if (useStmt.containsInvokeExpr()){
                InvokeExpr ie = useStmt.getInvokeExpr();
                SootMethod invokeMeth = ie.getMethod();

                if (invokeMeth.getSignature().equals(type.getSig())){
                    set.add(MethodContext.v(sm, useStmt));
                }

                // TODO application class
                else if (ie.getArgs().contains(target) && info.isApplicationClass(ie.getMethod().getDeclaringClass())){
                    IdentityStmt idStmt = getArgParamRef(invokeMeth, getIndex(ie, target));
                    set.addAll(findTargetCalls(MethodContext.v(invokeMeth, idStmt), type));
                }
            }

            // 2. 赋值给了Field, -> leftop
            else if (useStmt instanceof AssignStmt){
                if (((AssignStmt) useStmt).getRightOp().equals(target)){
                    Value leftOp = ((AssignStmt) useStmt).getLeftOp();

                    if (leftOp instanceof FieldRef){
                        SootField field = ((FieldRef) leftOp).getField();

                        if (!computedFields.contains(field)){
                            computedFields.add(field);
                            set.addAll(findTargetFieldCalls(field, type));
                        }
                    }
                    else {
                        mLogger.info("Unresolved assign to {}    Value : {}", leftOp, target);
                    }
                }

            }
            // 3. 作为返回值返回至caller
            else if (useStmt instanceof ReturnStmt){
                Iterator<Edge> ite = mCallGraph.edgesInto(sm);
                while (ite.hasNext()){
                    Edge edge = ite.next();
                    SootMethod caller = edge.src();

                    if (computedCaller.contains(caller))
                        continue;
                    computedCaller.add(caller);
                    Unit callingUnit = edge.srcUnit();

                    if (callingUnit instanceof AssignStmt){
                        assert ((AssignStmt) callingUnit).getLeftOp() instanceof Local;
                        set.addAll(findTargetCalls(MethodContext.v(caller, callingUnit), type));
                    }
                    else
                        mLogger.info("Unresolved calling unit : {}    Return value : {}", callingUnit, target);
                }
            }


        }
        return set;
    }

    /**
     * 获取对应index实参的identitystmt
     * @param callee
     * @param argIndex
     * @return
     */
    private IdentityStmt getArgParamRef(SootMethod callee, int argIndex){
        if (!callee.hasActiveBody()){
            return null;
        }

        Body body = callee.retrieveActiveBody();
        Iterator<Unit> ite = body.getUnits().snapshotIterator();

        while(ite.hasNext()) {
            Unit unit = ite.next();
            if (!(unit instanceof IdentityStmt)) {
                break;
            }
            IdentityStmt stmt = (IdentityStmt) unit;
            Value rightOp = stmt.getRightOp();
            if (rightOp instanceof ParameterRef) {
                if (((ParameterRef) rightOp).getIndex() == argIndex) {
                    return stmt;
                }
            }
        }

        return null;
    }

    /**
     * 在invokeexpr中找到目标value对应的arg序号
     * @param ie
     * @param arg
     * @return
     */
    private int getIndex(InvokeExpr ie, Value arg){
        for (int i = 0; i < ie.getArgs().size(); i++){
            if (arg.equals(ie.getArg(i))){
                return i;
            }
        }
        return -1;
    }

    /**
     * 对于field，需要考虑的情况为field在其他方法内部传递 -> rightop
     * 然后对于赋值的local，继续进行findtargetcalls()
     * @param field
     * @return
     */
    private Set<MethodOrMethodContext> findTargetFieldCalls(SootField field, ClientUseType type){
        Set<MethodOrMethodContext> set = new HashSet<>();

        SootClass declass = field.getDeclaringClass();
        for (SootMethod sm : declass.getMethods()){
            if (sm.hasActiveBody()){

                for (Unit u : sm.getActiveBody().getUnits()){
                    if (u.toString().contains(field.getSignature())){

                        // 只有field作为rightop，才进行分析
                        if (u instanceof AssignStmt){
                            Value rightOp = ((AssignStmt) u).getRightOp();
                            if (rightOp instanceof FieldRef && ((FieldRef) rightOp).getField().equals(field)){
                                Value leftOp = ((AssignStmt) u).getLeftOp();

                                if (leftOp instanceof Local){
                                    set.addAll(findTargetCalls(MethodContext.v(sm, u),type));
                                }
                                else
                                    mLogger.info("Unresolved type assign to {}   field : {}", leftOp, field.getSignature());
                            }
                        }

                    }

                }
            }
        }
        return set;

    }

    /**
     *  分情况，如果是直接匿名内部类，则在outerclass中找addintercrptor处
     *  如果在自己实现的intercepter类中的话，则需要全局搜索init处
     * @param sc
     * @param interceptor
     */
    private Set<TrackModel> findClientAddSpecInterceptor(SootClass interceptor){
        // 1.收集addinterceptor的client们
       Set<TrackModel> resSet = new HashSet<>();
        if (interceptor.hasOuterClass()){
            SootClass sc = interceptor.getOuterClass();
            resSet.addAll(scanMethForAddInterceptor(sc, interceptor));
        }


        else {
            for (SootClass sc : Scene.v().getApplicationClasses()){
                if (info.isApplicationClass(sc)){
                    if (scanMethForAddInterceptor(sc, interceptor).size() > 0){
                        resSet.addAll(scanMethForAddInterceptor(sc, interceptor));
                    }

                }
            }
        }
        return resSet;
    }
    /**
     * 收集 $r2 = virtualinvoke $r3.<okhttp3.OkHttpClient$Builder: okhttp3.OkHttpClient build()> 语句
     * 左侧全为client
     * @param sm
     * @param unit
     * @param clientBuilder
     * @return
     */
    private Set<TrackModel> getClientBuildPieces(SootMethod sm, Unit unit, Value clientBuilder){

        Set<TrackModel> resSet = new HashSet<>();
        //Map<SootMethod, Set<ValueUnitPair>> map = new HashMap<>();

        // 1. build()方法在该addinterceptor语句对应的method内部
        if (scanLowerUnit(sm, unit, CLIENT_BUILDER_BUILD_SIG, clientBuilder, null) != null){
            Unit buildUnit = scanLowerUnit(sm, unit, CLIENT_BUILDER_BUILD_SIG, clientBuilder, null);

            if (buildUnit instanceof AssignStmt){
                Value leftOp = ((AssignStmt) buildUnit).getLeftOp();
                resSet.add(new TrackModel(sm, buildUnit, leftOp));

            }
            else {
                mLogger.info("Warn : The client build unit is not AssignStmt. ");
            }

        }

        // 2. 还有种情况是clientbuilder作为返回值返回，则需要在caller处继续往下找，递归
        else if (isReturnOp(sm, clientBuilder)){
            CallGraph callGraph = Scene.v().getCallGraph();
            Iterator<Edge> iter = callGraph.edgesInto(sm);

            while (iter.hasNext()){
                Edge edge = iter.next();
                SootMethod caller = edge.src();
                Unit callingUnit = edge.srcUnit();

                assert callingUnit instanceof AssignStmt;
                Value builderNext = ((AssignStmt) callingUnit).getLeftOp();

                if (builderNext instanceof Local){
                    Set<TrackModel> pieces = getClientBuildPieces(caller, callingUnit, builderNext);
                    resSet.addAll(pieces);
                }
            }
        }
        // 3. 有没有可能clientbuilder赋值给了sootfield？
        else {
            mLogger.info("Tip : client builder is neither build or as return op in method {}", sm.getSignature());
        }

        return resSet;
    }

    private List<ReturnStmt> getReturnStmt(SootMethod sm) {
        List<ReturnStmt> returnUnits = new ArrayList<>();
        for (Unit unit : sm.getActiveBody().getUnits()) {
            Stmt stmt = (Stmt) unit;
            if (stmt instanceof ReturnStmt) {
                returnUnits.add((ReturnStmt) stmt);
            }
        }
        return returnUnits;
    }

    /**
     * 判断一个value是否作为返回值返回
     * @param sm
     * @param value
     * @return
     */
    private boolean isReturnOp(SootMethod sm, Value value){
        List<ReturnStmt> list = getReturnStmt(sm);
        for (ReturnStmt returnStmt : list){
            if (returnStmt.getOp().equals(value)){
                return true;
            }
        }
        return false;
    }

    /**
     *  在给定的sc的所有语句搜索addInterceptor(interceptor)的语句，锁定对象client
     * @param sc
     * @param interceptor
     * @return 返回的是 $r1(client) = <... : build()>
     * 这样的语句，value锁定的是client
     */
    private Set<TrackModel> scanMethForAddInterceptor(SootClass sc, SootClass interceptor){
        Set<TrackModel> resSet = new HashSet<>();

        for (SootMethod sm : sc.getMethods()){

            if (sm.hasActiveBody()){
                for (Unit unit : sm.retrieveActiveBody().getUnits()){
                    Stmt stmt = (Stmt) unit;

                    if (stmt.containsInvokeExpr() && stmt.getInvokeExpr() instanceof InstanceInvokeExpr){
                        InstanceInvokeExpr ie = (InstanceInvokeExpr) stmt.getInvokeExpr();

                        if (ie.getMethod().getSignature().equals(OKHTTP_ADD_INTERCEPTOR_SIG)){
                            if (ie.getArg(0).getType().toString().equals(interceptor.getName())){
                                UnitValueBoxPair cbPair = new UnitValueBoxPair(unit, ie.getBaseBox());

                                Set<TrackModel> clientSet = getClientBuildPieces(sm, cbPair.getUnit(), cbPair.getValueBox().getValue());
                                resSet.addAll(clientSet);
                            }
                        }
                    }

                    /*if (stmt instanceof AssignStmt){
                        Value rightOp = ((AssignStmt) stmt).getRightOp();
                        if (rightOp instanceof NewExpr && ((NewExpr) rightOp).getBaseType().getSootClass().equals(interceptor)){

                            Value leftOp = ((AssignStmt) stmt).getLeftOp();


                            if (leftOp instanceof Local){
                                UnitGraph unitGraph = new BriefUnitGraph(sm.getActiveBody());
                                LocalDefs localDefs = new SimpleLocalDefs(unitGraph);
                                LocalUses localUses = new SimpleLocalUses(unitGraph, localDefs);


                                UnitValueBoxPair cbPairs = getAddInterClientBuilder((Local) leftOp, stmt, localUses);
                                if (cbPairs != null){
                                    Set<TrackModel> clientSet = getClientBuildPieces(sm, cbPairs.getUnit(),cbPairs.getValueBox().getValue());
                                    resSet.addAll(clientSet);
                                }


                                *//*List<UnitValueBoxPair> useUnits = localUses.getUsesOf(stmt);
                                for (UnitValueBoxPair pair : useUnits){
                                    Stmt useStmt = (Stmt) pair.getUnit();

                                    if (useStmt.containsInvokeExpr()
                                            && useStmt.getInvokeExpr().getMethod().getSignature().equals(Constants.OKHTTP_ADD_INTERCEPTOR_SIG)
                                            && useStmt.getInvokeExpr().getArg(0).equals(leftOp)){

                                        assert useStmt.getInvokeExpr() instanceof InstanceInvokeExpr;

                                        Value clientBase = ((InstanceInvokeExpr) useStmt.getInvokeExpr()).getBase();
                                        Set<TrackModel> clientSet = getClientBuildPieces(sm, useStmt, clientBase);
                                        resSet.addAll(clientSet);
                                    }

                                    else if (useStmt instanceof AssignStmt){
                                        Value right = ((AssignStmt) useStmt).getRightOp();
                                        if (right instanceof CastExpr){
                                            Value value = ((CastExpr) right).getOp();
                                            if (value.equals(leftOp)){
                                                localDefs.getDefsOfAt((Local) ((AssignStmt) useStmt).getLeftOp(), useStmt);

                                            }
                                        }

                                    }

                                }*//*
                            }
                            else {
                                mLogger.info("Warn : Unresolved new expr type {}.", stmt);
                            }


                        }
                    }*/
                }
            }
        }
        return resSet;
    }

    /**
     * 从 $r1 = new Interceptorxxx; 开始，找到
     * @param interceptor
     * @param unit
     * @param localUses
     * @return
     */
    private UnitValueBoxPair getAddInterClientBuilder(Local interceptor, Unit unit, LocalUses localUses){
        List<UnitValueBoxPair> pairs = localUses.getUsesOf(unit);

        for (UnitValueBoxPair pair : pairs){
            Stmt useUnit = (Stmt) pair.getUnit();

            if (useUnit.containsInvokeExpr()){
                InvokeExpr ie = useUnit.getInvokeExpr();
                if (ie.getMethod().getSignature().equals(OKHTTP_ADD_INTERCEPTOR_SIG)
                        &&ie.getArg(0).equals(interceptor)){
                    return new UnitValueBoxPair(useUnit, ((InstanceInvokeExpr)ie).getBaseBox());
                }
            }

            if (useUnit instanceof AssignStmt){
                Value rightOp = ((AssignStmt) useUnit).getRightOp();
                Value leftOp = ((AssignStmt) useUnit).getLeftOp();
                if (rightOp instanceof CastExpr && leftOp instanceof Local){
                    if (((CastExpr) rightOp).getOp().equals(interceptor)){

                        return getAddInterClientBuilder((Local) leftOp, useUnit, localUses);
                    }
                }
            }
        }
        return null;
    }

    /**
     * 往上遍历语句，获取目标targetbase作为对象的targetmeth调用语句。
     * 为什么不采用localdefs或者localuses，因为这些方法每次执行都会更新一下对象，所以无法找全
     * @param meth 当前搜索的method
     * @param thisUnit 当前起始的unit
     * @param targetMethSig 目标调用方法
     * @param targetBase 锁定的对象
     * @param upperLimitMethSig 上限，可为null或空，即默认遍历至方法头语句
     * @return 目标调用处
     */
    private Unit scanUpperUnit(SootMethod meth, Unit thisUnit, String targetMethSig, Value targetBase, String upperLimitMethSig){
        Body body = meth.getActiveBody();

        while (body.getUnits().getPredOf(thisUnit) != null){
            Unit preUnit = body.getUnits().getPredOf(thisUnit);
            Stmt preStmt = (Stmt) preUnit;

            if (preStmt.containsInvokeExpr()){
                InvokeExpr ie = preStmt.getInvokeExpr();
                SootMethod invokeMeth = ie.getMethod();

                if (upperLimitMethSig != null && !upperLimitMethSig.isEmpty()
                        && invokeMeth.getSignature().equals(upperLimitMethSig)){
                    break;
                }

                if (invokeMeth.getSignature().equals(targetMethSig)){
                    assert ie instanceof InstanceInvokeExpr;
                    if (((InstanceInvokeExpr) ie).getBase().equals(targetBase)){
                        return preUnit;
                    }
                }
            }

            thisUnit = preUnit;
        }

        return null;
    }


    /**
     * 找到设置目标client的retrofitbuilder设置的baseurl
     * virtualinvoke $r1.<retrofit2.Retrofit$Builder: retrofit2.Retrofit$Builder client(okhttp3.OkHttpClient)>($r3);
     * @param builder
     * @param u
     * @param sm
     * @return
     */
    private Set<TrackModel> getBaseUrlForRetrofit(TrackModel builderModel){
        Set<TrackModel> result = new HashSet<>();

        Value base = builderModel.getTargetValue();
        Stmt s = (Stmt) builderModel.getLocateUnit();

        SimpleLocalDefs localDefs = new SimpleLocalDefs(builderModel.getUnitGraph());
        LocalUses localUses = new SimpleLocalUses(builderModel.getUnitGraph(), localDefs);

        Unit defUnit = getDefinition((Local) base, s, localDefs);
        List<UnitValueBoxPair> uses = localUses.getUsesOf(defUnit);

        for (UnitValueBoxPair use : uses){
            Unit useUnit = use.getUnit();
            Stmt useStmt = (Stmt) useUnit;

            if (useStmt.toString().contains("<retrofit2.Retrofit$Builder: retrofit2.Retrofit$Builder baseUrl(okhttp3.HttpUrl)>")){
                // TODO tranverse HttpUrl -> String
                // $r10 = staticinvoke <okhttp3.HttpUrl: okhttp3.HttpUrl parse(java.lang.String)>($r9);
                result.addAll(trackHttpUrlParse((Local) useStmt.getInvokeExpr().getArg(0), useStmt, builderModel.getLocateMethod()));

            }
            else if (useStmt.toString().contains("<retrofit2.Retrofit$Builder: retrofit2.Retrofit$Builder baseUrl(java.lang.String)>")){
                result.add(new TrackModel(builderModel.getLocateMethod(), useUnit, useStmt.getInvokeExpr().getArg(0)));
            }

            else if (useStmt.toString().contains("retrofit2.Retrofit$Builder: retrofit2.Retrofit$Builder baseUrl")){
                mLogger.info("Unresolved baseUrl arg type. " + useStmt.getInvokeExpr().getArg(0).getType().toString());
            }
        }

        return result;
    }


    private Set<TrackModel> trackHttpUrlParse(Local httpUrl, Unit s, SootMethod meth) {
        Set<TrackModel> result = new HashSet<>();

        UnitGraph unitGraph = new ExceptionalUnitGraph(meth.getActiveBody());
        SimpleLocalDefs localDefs = new SimpleLocalDefs(unitGraph);

        Unit defUnit = getDefinition(httpUrl, s, localDefs);

        if (defUnit instanceof IdentityStmt) {
            ParameterRef parameterRef = (ParameterRef) ((IdentityStmt) defUnit).getRightOp();
            int index = parameterRef.getIndex();
            Iterator<Edge> ite = mCallGraph.edgesInto(meth);

            while (ite.hasNext()){
                Edge edge = ite.next();
                SootMethod caller = edge.src();
                Stmt callingStmt = edge.srcStmt();

                result.addAll(Objects.requireNonNull(trackHttpUrlParse((Local) callingStmt.getInvokeExpr().getArg(index), callingStmt, caller)));
            }

        } else if (defUnit instanceof AssignStmt){
            Value rightOp = ((AssignStmt) defUnit).getRightOp();

            if (rightOp instanceof InvokeExpr){
                String invokeSig = ((InvokeExpr) rightOp).getMethod().getSignature();
                if (invokeSig.equals("<okhttp3.HttpUrl: okhttp3.HttpUrl parse(java.lang.String)>")){
                    result.add(new TrackModel(meth, defUnit, ((InvokeExpr) rightOp).getArg(0))) ;
                }
                else if (invokeSig.equals("<okhttp3.HttpUrl$Builder: okhttp3.HttpUrl build()>")){
                    return trackHttpUrlParse((Local) ((AssignStmt) defUnit).getLeftOp(), defUnit, meth);
                }
            }
        }
        return result;
    }



    private Stmt getDefinition(Local local, Unit u, SimpleLocalDefs localDefs){
        return SessCallGraphBuilder.getDefinition(local, u, localDefs);
    }
    /**
     * 扫描meth中在thisunit之后的每句unit，如果是同一个targetbase对象的目标调用方法targetmethsig，则返回该句
     * @param meth 目前方法
     * @param thisUnit 目前位置
     * @param targetMethSig 调用方法
     * @param targetBase 对象
     * @param lowerLimitMethSig 下限
     * @return
     */
    private Unit scanLowerUnit(SootMethod meth, Unit thisUnit, String targetMethSig, Value targetBase, String lowerLimitMethSig){
        if (!scanLowerUnits(meth, thisUnit, targetMethSig, targetBase, lowerLimitMethSig, false).isEmpty()){
            return scanLowerUnits(meth, thisUnit, targetMethSig, targetBase, lowerLimitMethSig, false).get(0);
        }
        return null;
    }

    private List<Unit> scanLowerUnits(SootMethod meth, Unit thisUnit, String targetMethSig, Value targetBase, String lowerLimitMethSig, boolean isMulti){
        List<Unit> resultUnits = new ArrayList<>();
        Body body = meth.getActiveBody();

        while (body.getUnits().getSuccOf(thisUnit) != null){
            Unit succUnit = body.getUnits().getSuccOf(thisUnit);
            Stmt succStmt = (Stmt) succUnit;

            if (succStmt.containsInvokeExpr()){
                InvokeExpr ie = succStmt.getInvokeExpr();
                SootMethod invokeMeth = ie.getMethod();

                if (lowerLimitMethSig != null && !lowerLimitMethSig.isEmpty()
                        && invokeMeth.getSignature().equals(lowerLimitMethSig)){
                    break;
                }

                if (invokeMeth.getSignature().equals(targetMethSig)){
                    assert ie instanceof InstanceInvokeExpr;
                    if (((InstanceInvokeExpr) ie).getBase().equals(targetBase)) {
                        resultUnits.add(succStmt);
                        if (!isMulti){
                            break;
                        }
                    }

                }
            }

            thisUnit = succUnit;
        }
        return resultUnits;
    }

    /**
     * 判断该addheader()语句是否写在interceptor内部（Response intercept(Interceptor.Chain chain)
     * @param meth
     * @param unit
     * @param requestBuilder
     * @return
     */
    public boolean isWrittenIntercept(SootMethod meth, int index){
        if (index == 3){
            return false;
        }
        if (isDirectIntercept(meth)){
            return true;
        }


        for (SootMethod caller : getJustCallers(meth)){
            if (isDirectIntercept(caller)){
                return true;
            }
            else {
                return isWrittenIntercept(caller, ++index);
            }
        }
        return false;
    }

    /**
     * 判断该方法是否为Interceptor.intercept()方法
     * @param meth
     * @return
     */
    public boolean isDirectIntercept(SootMethod meth){
        SootClass sc = meth.getDeclaringClass();

        if (sc.implementsInterface("okhttp3.Interceptor")
                && meth.getSubSignature().equals("okhttp3.Response intercept(okhttp3.Interceptor$Chain)")){
            mInterceptorClass = sc;
            return true;
        }
        return false;
    }

    private void bindRetroClass(MethodOrMethodContext retroClientPair){

        SootMethod sm = retroClientPair.method();
        Stmt clientStmt = (Stmt) retroClientPair.context();

        UnitGraph unitGraph = new BriefUnitGraph(sm.getActiveBody());

        if (clientStmt.getInvokeExpr() instanceof InstanceInvokeExpr){

            Value retroBuilder = ((InstanceInvokeExpr) clientStmt.getInvokeExpr()).getBase();
            ValueUnitPair retroPair = findRetroValue(unitGraph, clientStmt, retroBuilder);

            if (retroPair != null){
                SootClass cl = getRetroClass(unitGraph, retroPair.getUnit(), retroPair.getValue());
                if (cl != null){
                    this.retroClasses.add(cl);
                }
                else
                    mLogger.info("Warn : can not find the bind retro class in {}.", sm.getSignature());
            }
            else
                mLogger.info("Warn : can not find the Retrofit build() info.");
        }
        else {
            mLogger.info("To fix : <Retrofit$Builder: client()> is strange.");
        }

    }

    /**
     * 从retrofit$Builder: client(xx)方法之后获取该builder经build()之后的retrofit local
     * @param unitGraph
     * @param unit
     * @param retroBuild
     * @return
     */
    private ValueUnitPair findRetroValue(UnitGraph unitGraph, Unit unit, Value retroBuild){
        for (Unit uu : unitGraph.getSuccsOf(unit)){

            if (uu.toString().contains("<retrofit2.Retrofit$Builder: retrofit2.Retrofit build()>")){
                Stmt ss = (Stmt) uu;

                if (ss instanceof AssignStmt){
                    assert ss.getInvokeExpr() instanceof InstanceInvokeExpr;

                    if (((InstanceInvokeExpr) ss.getInvokeExpr()).getBase().equals(retroBuild)){
                        Value leftOp = ((AssignStmt) ss).getLeftOp();
                        return new ValueUnitPair(leftOp, uu);
                    }
                }
                else {
                    mLogger.info("<Retrofit$Builder: build()> is not AssignStmt.");
                }

            }

            else
                return findRetroValue(unitGraph, uu, retroBuild);
        }

        return null;
    }

    /**
     * 从$r0 = virtualinvoke $r1.<retrofit2.Retrofit$Builder: retrofit2.Retrofit build()>();开始往下寻找$r0的create class
     * @param unitGraph
     * @param cUnit
     * @param base
     * @return
     */
    private SootClass getRetroClass(UnitGraph unitGraph, Unit cUnit, Value base){

        for (Unit unit : unitGraph.getSuccsOf(cUnit)){

            if (unit.toString().contains("<retrofit2.Retrofit: java.lang.Object create(java.lang.Class)>")){
                Stmt stmt = (Stmt) unit;
                if (!stmt.containsInvokeExpr()){
                    System.out.println("ERROR: " + stmt + " has no invoke expr.");
                    break;
                }

                InstanceInvokeExpr iie = (InstanceInvokeExpr) stmt.getInvokeExpr();
                Value retroBu = iie.getBase();

                if (retroBu.equals(base)){
                    Value param = iie.getArg(0);

                    if (param instanceof ClassConstant){
                        String str = ((ClassConstant) param).getValue();

                        str = str.substring(1, str.length()-1).replaceAll("/", ".");

                        return Scene.v().forceResolve(str, SootClass.BODIES);
                    }

                    //TODO expend
                }

            }

            else {
                return getRetroClass(unitGraph, unit, base);
            }
        }

        return null;
    }


    private Set<MethodOrMethodContext> getCallers(SootMethod callee){
        Set<MethodOrMethodContext> callingInfo = new HashSet<>();

        Iterator<Edge> ite = mCallGraph.edgesInto(callee);
        while (ite.hasNext()){
            Edge edge = ite.next();
            Unit callingUnit = edge.srcUnit();
            SootMethod caller = edge.src();
            callingInfo.add(MethodContext.v(caller, callingUnit));
        }
        return callingInfo;
    }

    private Set<SootMethod> getJustCallers(SootMethod callee){
        Set<SootMethod> result = new HashSet<>();
        Iterator<Edge> ite = mCallGraph.edgesInto(callee);
        while (ite.hasNext()){
            Edge edge = ite.next();
            SootMethod caller = edge.src();
            result.add(caller);
        }
        return result;
    }
}
