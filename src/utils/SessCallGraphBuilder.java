package utils;

import configs.AppInfoConfig;
import exceptions.NullDefException;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.util.NumberedString;

import java.util.*;

public class SessCallGraphBuilder {
    static CallGraph cg = null;
    static List<Edge> edges = new LinkedList<>();
    static List<Edge> clinitEdges = new LinkedList<>();
    static Set<String> excludedCalls = new HashSet<>();

    /**
     * retrieve all active method body
     */
    public static void retrieveActiveBodies(){
        SessDroidLogger.Log("Retrieving active bodies for call graph...");

        for(SootClass sc: Scene.v().getClasses()){
            // Check whether this SootClass is phantom
            if(sc.isPhantom())
                continue;

            for(SootMethod sm : sc.getMethods()){
                try {
                    // Get active body
                    retrieveActiveBody(sm);
                } catch (Exception e) {
                    SessDroidLogger.Warn("Err_Method: " + sm.toString());
                    //e.printStackTrace();
                    continue;
                }
            }
        }

        SessDroidLogger.Log("All active bodies have been retrieved.");
    }

    /** Retrieve the active body of the SootMethod if the body legal;
     *
     * @param m target SootMethod
     */
    private static void retrieveActiveBody(SootMethod m){
        if (!m.isConcrete()) return;
        if (m.isAbstract()) return;
        if (m.isNative()) return;
        if (m.isPhantom()) return;

        // Retrieve the active body
        if (!m.hasActiveBody())
            m.retrieveActiveBody();
    }

    /**
     * invoke after retrieveActiveBodies()
     * @return
     */
    public static CallGraph buildAndGet() {
        cg = new CallGraph();

        buildCallGraph();

        return cg;
    }

    public static CallGraph getCg(){
        return cg;
    }

    private static void buildCallGraph(){
        SessDroidLogger.Log("Building call graph...");
        init();

        Iterator<SootClass> scIte = Scene.v().getClasses().snapshotIterator();
        while (scIte.hasNext()){
            SootClass sc = scIte.next();
            if(sc.isPhantom())
                continue;


            for (int i = 0; i < sc.getMethods().size(); i++){
                SootMethod sm = sc.getMethods().get(i);
                if (!sm.hasActiveBody()){
                    continue;
                }

                Iterator<Unit> unitIterator = sm.getActiveBody().getUnits().snapshotIterator();

                while (unitIterator.hasNext()){
                    Unit u = unitIterator.next();
                    Stmt s = (Stmt) u;

                    // Reset the edge/clinitEdge lists
                    clearLists();

                    // invoke expression check
                    if (!s.containsInvokeExpr())
                        continue;

                    InvokeExpr ie = s.getInvokeExpr();

                    if (isExcludedCall(ie))
                        continue;

                    // Volley is special, add override onResponse() method edge from the init of the Request<T> class
                    //addVolleyResponseEdge(sm, s, ie);

                    if (!implicitCall(sm, s)){
                        if (isSystemPackage(s))
                            continue;

                        /*if (ie instanceof InterfaceInvokeExpr){
                            interfaceInvokeHandler(sm, s);
                        }
                        else if (ie instanceof StaticInvokeExpr){
                            staticInvokeHandler(sm, s);
                        }
                        else if (ie instanceof VirtualInvokeExpr){
                            virtualInvokeHandler(sm, s);
                        }
                        else if (ie instanceof SpecialInvokeExpr){
                            specialInvokeHandler(sm, s);
                        }*/

                        edges.add(new Edge(sm, s, ie.getMethod()));
                    }

                    //TODO
                    //clinitHandler(sm, s);

                    addEdgesToCallGraph();
                }
            }
        }

        SessDroidLogger.Log("Call graph has been generated.");

    }

    private static void addVolleyResponseEdge(SootMethod currentSm, Stmt s, InvokeExpr ie){
        SootMethod invokeSm = ie.getMethod();
        if (!invokeSm.getName().equals("<init>"))
            return;
        if (!VolleyUtils.isVolleyRequestSubClass(ie.getMethod().getDeclaringClass()))
            return;

        for (int i = 0; i < invokeSm.getParameterTypes().size(); i++){
            Type paramType = invokeSm.getParameterType(i);
            if (paramType.toString().equals("com.android.volley.Response$Listener")){
                NumberedString sigCustom = Scene.v().getSubSigNumberer().findOrAdd("volley.StringRequest: void <init>()");
                implicitCallHandleInternal(sigCustom, ie, currentSm, s, i);
                break;
            }
        }
    }

    private static void interfaceInvokeHandler(SootMethod currentSm, Stmt s){
        InvokeExpr ie = s.getInvokeExpr();
        SootClass sc = ie.getMethodRef().getDeclaringClass();

        if (!sc.isInterface()){
            return;
        }

        // Get implementers of the declaring class
        List<SootClass> imples = Scene.v().getActiveHierarchy().getImplementersOf(sc);

        for (SootClass imple : imples){
            SootMethod targetSm = imple.getMethodUnsafe(ie.getMethodRef().getSubSignature());

            if (!isValidMethod(targetSm))
                continue;

            edges.add(new Edge(currentSm, s, targetSm));
        }

    }


    private static void staticInvokeHandler(SootMethod currentSm, Stmt s){
        InvokeExpr ie = s.getInvokeExpr();
        SootClass sc = ie.getMethodRef().getDeclaringClass();
        SootMethod targetSm = sc.getMethodUnsafe(ie.getMethodRef().getSubSignature());

        if (isValidMethod(targetSm)){
            edges.add(new Edge(currentSm, s, targetSm));
        }
        else{
            List<SootClass> superClasses = Scene.v().getActiveHierarchy().getSuperclassesOf(sc);

            for (SootClass superClass : superClasses){
                targetSm = superClass.getMethodUnsafe(ie.getMethodRef().getSubSignature());

                // Check whether the super class contains the corresponding method
                if (!isValidMethod(targetSm))
                    continue;

                // Add the corresponding method and exit when it exist
                edges.add(new Edge(currentSm, s, targetSm));
                break;
            }
        }
    }

    /**
     * Handle virtual invoke (Need to consider both of sub-classes and super-classes)
     * @param currentSm
     * @param s
     */
    private static void virtualInvokeHandler(SootMethod currentSm, Stmt s){
        InvokeExpr ie = s.getInvokeExpr();
        SootClass sc = ie.getMethodRef().getDeclaringClass();
        SootMethod targetSm = sc.getMethodUnsafe(ie.getMethodRef().getSubSignature());

        if (isValidMethod(targetSm)){
            edges.add(new Edge(currentSm, s, targetSm));
        }

        // Get the sub-classes of the declaring class
        List<SootClass> subClasses = Scene.v().getActiveHierarchy().getSubclassesOf(sc);
        for(SootClass subClass : subClasses){
            targetSm = subClass.getMethodUnsafe(ie.getMethodRef().getSubSignature());
            if(!isValidMethod(targetSm))
                continue;

            // Add the corresponding method of the sub-class when it exists
            edges.add(new Edge(currentSm, s, targetSm));
        }

        // Get the super-classes of the declaring class
        List<SootClass> superClasses = Scene.v().getActiveHierarchy().getSuperclassesOf(sc);
        for (SootClass superClass : superClasses) {
            targetSm = superClass.getMethodUnsafe(ie.getMethodRef().getSubSignature());
            if (!isValidMethod(targetSm))
                continue;

            // Add the corresponding method of the sub-class when it exists
            edges.add(new Edge(currentSm, s, targetSm));
        }
    }

    private static void specialInvokeHandler(SootMethod currentSm, Stmt s){
        InvokeExpr ie = s.getInvokeExpr();

        if (Scene.v().containsMethod(ie.getMethodRef().getSignature())){
            if (isValidMethod(ie.getMethod())){
                edges.add(new Edge(currentSm, s, ie.getMethod()));
            }
        }
    }


    private static boolean isSystemPackage(Stmt s){
        InvokeExpr ie = s.getInvokeExpr();
        return AppInfoConfig.isClassInSystemPackage
                (ie.getMethodRef().getDeclaringClass().toString());
    }


    private static boolean implicitCall(SootMethod currentSm, Stmt s){
        InvokeExpr ie = s.getInvokeExpr();

        //final NumberedString sigRun = Scene.v().getSubSigNumberer().findOrAdd("void run()");
        final NumberedString sigFutureSubmit = Scene.v().getSubSigNumberer().findOrAdd("java.util.concurrent.Future submit(java.lang.Runnable)");

        //final NumberedString sigIntercept = Scene.v().getSubSigNumberer().findOrAdd("okhttp3.Response intercept(okhttp3.Interceptor$Chain)");
        final NumberedString sigAddInterceptor = Scene.v().getSubSigNumberer().findOrAdd("okhttp3.OkHttpClient$Builder addInterceptor(okhttp3.Interceptor)");
        final NumberedString sigSetClickListener = Scene.v().getSubSigNumberer().findOrAdd("void setOnClickListener(android.view.View$OnClickListener)");
        final NumberedString sigEnqueueRetro = Scene.v().getSubSigNumberer().findOrAdd("void enqueue(retrofit2.Callback)");
        final NumberedString sigEnqueueOkhttp = Scene.v().getSubSigNumberer().findOrAdd("void enqueue(okhttp3.Callback)>");
        final NumberedString sigAddVolleyRequest = Scene.v().getSubSigNumberer().findOrAdd("com.android.volley.Request add(com.android.volley.Request)>");
        final NumberedString sigAsyncHttpGet = Scene.v().getSubSigNumberer().findOrAdd("com.loopj.android.http.RequestHandle get(java.lang.String,com.loopj.android.http.ResponseHandlerInterface)");
        final NumberedString sigAsyncHttpPost = Scene.v().getSubSigNumberer().findOrAdd("com.loopj.android.http.RequestHandle post(java.lang.String,com.loopj.android.http.RequestParams,com.loopj.android.http.ResponseHandlerInterface)");
        //TODO add


        if (ie instanceof InstanceInvokeExpr){
            InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
            NumberedString subSig = iie.getMethodRef().getSubSignature();

            /**
             * Runnable runnable = new Runnable() {
             *    public void run() {
             *       System.out.println("This is ThreadPoolExetor#submit(Runnable runnable) method.");
             *    }
             * };
             *
             * Future future = executor.submit(runnable);
             */// add edge from submit(Runnable) to its @override run() method
            //TODO add
            if (subSig.equals(sigFutureSubmit)
                    || subSig.equals(sigAddInterceptor)
                    /*|| subSig.equals(sigSetClickListener)
                    || subSig.equals(sigEnqueueRetro)
                    || subSig.equals(sigEnqueueOkhttp)
                    || subSig.equals(sigAddVolleyRequest)*/){

                implicitCallHandleInternal(subSig, iie, currentSm, s, 0);
                /*Value runnable = iie.getArg(0);

                // Get the class(type) of the argument
                SootClass sc = Scene.v().getSootClass(runnable.getType().toString());

                // Get 'void run()' method of the class(type) of the first argument
                SootMethod targetSM = sc.getMethodUnsafe(sigRun);

                if (isValidMethod(targetSM)){
                    edges.add(new Edge(currentSm, s, targetSM));
                } else if (!sc.isInterface()){//子类用的父类的run()方法
                    // Get the super-classes when the method of the declaring class does not exist
                    List<SootClass> superClasses = Scene.v().getActiveHierarchy().getSuperclassesOf(sc);

                    for (SootClass superClass : superClasses){
                        targetSM = superClass.getMethodUnsafe(sigRun);

                        // Check whether the super class contains the corresponding method
                        if (!isValidMethod(targetSM))
                            continue;

                        // Add the corresponding method and exit when it exist
                        edges.add(new Edge(currentSm, s, targetSM));
                        break;
                    }

                }*/
                return true;
            }
            /*else if (subSig.equals(sigAsyncHttpGet)){
                implicitCallHandleInternal(subSig, iie, currentSm, s, 1);
            }
            else if (subSig.equals(sigAsyncHttpPost)){
                implicitCallHandleInternal(subSig, iie, currentSm, s, 2);
            }*/

        }
        return false;
    }

    private static void implicitCallHandleInternal(NumberedString invokeSig, InvokeExpr ie, SootMethod currentSm, Stmt s, int index){
        Value value = ie.getArg(index);

        SootClass sc = Scene.v().getSootClass(value.getType().toString());
        NumberedString innerSig = getCorrespondingInnerSig(invokeSig.getString());
        SootMethod targetSM = sc.getMethodUnsafe(innerSig);

        if (isValidMethod(targetSM)) {
            edges.add(new Edge(currentSm, s, targetSM));
        }
        else if (!sc.isInterface()){
            List<SootClass> superClasses = Scene.v().getActiveHierarchy().getSuperclassesOf(sc);

            for (SootClass superClass : superClasses){
                targetSM = superClass.getMethodUnsafe(innerSig);

                if (!isValidMethod(targetSM))
                    continue;
                edges.add(new Edge(currentSm, s, targetSM));
                break;
            }
        }
        // cast case
        else if (sc.isInterface()){
            if (value instanceof Local) {
                sc = castHandler((Local) value, s, currentSm);
                if (sc != null) {
                    targetSM = sc.getMethodUnsafe(innerSig);

                    if (isValidMethod(targetSM)){
                        edges.add(new Edge(currentSm, s, targetSM));
                    }
                }

            }
        }
    }

    /**
     * if the type is interface, then it may be casted. this is a case:
     * $r15 = new com.league.theleague.activities.sms.AddPhoneFragment$showPhoneNumberLayout$3;
     * $r13 = (android.view.View$OnClickListener) $r15;
     * virtualinvoke $r14.<androidx.appcompat.widget.AppCompatButton: void setOnClickListener(android.view.View$OnClickListener)>($r13);
     * @param local
     * @param u
     * @param locateMethod
     * @return the real type sootclass
     */
    private static SootClass castHandler(Local local, Unit u, SootMethod locateMethod){
        UnitGraph unitGraph = new ExceptionalUnitGraph(locateMethod.getActiveBody());
        SimpleLocalDefs localDefs = new SimpleLocalDefs(unitGraph);

        Stmt defStmt = getDefinition(local, u, localDefs);
        if (defStmt instanceof AssignStmt){
            Value rightOp = ((AssignStmt) defStmt).getRightOp();
            if (rightOp instanceof CastExpr){
                Value castLocal = ((CastExpr) rightOp).getOp();

                return Scene.v().getSootClass(castLocal.getType().toString());
            }
        }

        return null;
    }


    public static Stmt getDefinition(Local local, Unit u, SimpleLocalDefs localDefs){
        List<Unit> defUnits = localDefs.getDefsOfAt(local, u);
        if (defUnits.size() == 0){
            throw new NullDefException();
        }

        return (Stmt) defUnits.get(0);
    }


    private static NumberedString getCorrespondingInnerSig(String invokeSig){
        NumberedString result;
        switch (invokeSig){
            case "java.util.concurrent.Future submit(java.lang.Runnable)":
                result = Scene.v().getSubSigNumberer().findOrAdd("void run()");
                break;
            case "okhttp3.OkHttpClient$Builder addInterceptor(okhttp3.Interceptor)":
                result = Scene.v().getSubSigNumberer().findOrAdd("okhttp3.Response intercept(okhttp3.Interceptor$Chain)");
                break;
/*            case "void setOnClickListener(android.view.View$OnClickListener)":
                result = Scene.v().getSubSigNumberer().findOrAdd("void onClick(android.view.View)");
                break;
            case "void enqueue(retrofit2.Callback)":
                result = Scene.v().getSubSigNumberer().findOrAdd("void onRequestResponse(retrofit2.Call,retrofit2.Response)");
                break;
            case "void enqueue(okhttp3.Callback)>":
                result = Scene.v().getSubSigNumberer().findOrAdd("void onResponse(okhttp3.Call,okhttp3.Response)");
                break;
            case "com.android.volley.Request add(com.android.volley.Request)>":
                result = Scene.v().getSubSigNumberer().findOrAdd("java.util.Map getHeaders()");
                break;
            case "com.loopj.android.http.RequestHandle get(java.lang.String,com.loopj.android.http.ResponseHandlerInterface)":
            case "com.loopj.android.http.RequestHandle post(java.lang.String,com.loopj.android.http.RequestParams,com.loopj.android.http.ResponseHandlerInterface)":
                result = Scene.v().getSubSigNumberer().findOrAdd("void onSuccess(int,cz.msebera.android.httpclient.Header[],byte[])");
                break;
            case "volley.StringRequest: void <init>()":
                result = Scene.v().getSubSigNumberer().findOrAdd("void onResponse(java.lang.Object)");
                break;*/
            default:
                result = null;
                break;
        }
        return result;
    }

    /** Add corresponding clinit method
     *
     * @param srcSM current method
     * @param s current statement
     */
    private static void clinitHandler(SootMethod srcSM, Stmt s){
        final NumberedString sigClinit = Scene.v().getSubSigNumberer().findOrAdd( "void <clinit>()" );

        for(Edge edge: edges){
            SootClass sc = edge.getTgt().method().getDeclaringClass();
            SootMethod targetSM = sc.getMethodUnsafe(sigClinit);

            // if the <clinit> exists in the class,
            if(isValidMethod(targetSM))
                // Add it to clinitEdgeList
                clinitEdges.add(new Edge(srcSM, s, targetSM));
        }
    }


    private static boolean isValidMethod(SootMethod m){
        return (m != null) && m.hasActiveBody();
    }

    /**
     * clear the edge/clinitEdge lists
     */
    private static void clearLists(){
        edges.clear();
        clinitEdges.clear();
    }

    private static void init() {
        excludedCalls.add("<rx.functions.Func1: java.lang.Object call(java.lang.Object)>");
    }

    private static boolean isExcludedCall(InvokeExpr ie) {
        String method = ie.getMethodRef().toString();
        return excludedCalls.contains(method);
    }

    private static void addEdgesToCallGraph(){
        for (Edge e : clinitEdges){
            cg.addEdge(e);
        }
        for (Edge e : edges){
            cg.addEdge(e);
        }
    }
}
