package analysis.pointsTo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Local;
import soot.Value;
import soot.jimple.Stmt;
import soot.jimple.infoflow.android.data.AndroidMethod;
import soot.jimple.infoflow.sourcesSinks.definitions.*;
import soot.toolkits.scalar.UnitValueBoxPair;
import soot.toolkits.scalar.ValueUnitPair;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 1. LocalStatementParser.fromSet(sources, sinks)
 *       sources -> Map<UnitValueBoxPair, String>() 所针对local。以及所在的方法对应签名
 *       sinks -> Set<String>() 以之前的SourcesAndSinks.txt 格式形式
 * 2. getSources()
 *       StatementSourceSinkDefinition 类型的source
 *    getSinks()
 *       MethodSourceSinkDefinition 类型的sink
 */
public class LocalStatementParser implements ISourceSinkDefinitionProvider {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final int INITIAL_SET_SIZE = 10000;

    private Set<ISourceSinkDefinition> sourceList = null;
    private Set<ISourceSinkDefinition> sinkList = null;
    private Map<String, AndroidMethod> methods = null;

    private Map<ValueUnitPair, String> sourceData;
    private List<String> sinkData;
    private List<String> additionSourceData;

    private final String regex = "^<(.+):\\s*(.+)\\s+(.+)\\s*\\((.*)\\)>\\s*(.*?)(\\s+->\\s+(.*))?$";
    // private final String regexNoRet =
    // "^<(.+):\\s(.+)\\s?(.+)\\s*\\((.*)\\)>\\s+(.*?)(\\s+->\\s+(.*))?+$";
    private final String regexNoRet = "^<(.+):\\s*(.+)\\s*\\((.*)\\)>\\s*(.*?)?(\\s+->\\s+(.*))?$";

    private LocalStatementParser(){
        this.sourceData = new HashMap<>();
        this.sinkData = new ArrayList<>();
    }

    private LocalStatementParser(Map<ValueUnitPair, String> sources, List<String> sinks){
        this.sourceData = sources;
        this.sinkData = sinks;
    }


    public static LocalStatementParser fromFile(Map<ValueUnitPair, String> sources, String sourceSinkFile) throws IOException {
        LocalStatementParser parser = new LocalStatementParser();
        parser.readFile(sourceSinkFile);
        if (sources != null){
            parser.sourceData.putAll(sources);
        }
        return parser;
    }


    public static LocalStatementParser fromSet(Map<ValueUnitPair, String> sources, List<String> sinks){
        LocalStatementParser parser = new LocalStatementParser(sources, sinks);
        return parser;
    }

    private void readFile(String fileName) throws IOException {
        FileReader fr = null;

        try {
            fr = new FileReader(fileName);
            this.readReader(fr);
        } finally {
            if (fr != null) {
                fr.close();
            }

        }

    }

    private void readReader(Reader r) throws IOException {
        this.sinkData = new ArrayList();
        this.additionSourceData = new ArrayList<>();

        BufferedReader br = new BufferedReader(r);

        String line;
        try {
            while((line = br.readLine()) != null) {
                this.sinkData.add(line);
                this.additionSourceData.add(line);
            }
        } finally {
            br.close();
        }
    }

    private void parse(){
        methods = new HashMap<>(INITIAL_SET_SIZE);
        sourceList = new HashSet<>(INITIAL_SET_SIZE);
        sinkList = new HashSet<>(INITIAL_SET_SIZE);

        if (sourceData != null){
            for (ValueUnitPair sourcePair : sourceData.keySet()){
                Stmt unit = (Stmt) sourcePair.getUnit();
                Value value = sourcePair.getValue();

                if (value instanceof Local){
                    StatementSourceSinkDefinition singleStatement = new StatementSourceSinkDefinition(unit, (Local) value, null);
                    sourceList.add(singleStatement);
                }
                else{
                    logger.warn( String.format("Source statement does not match: %s in %s", sourcePair, sourceData.get(sourcePair)));
                }
            }
        }

        Pattern p = Pattern.compile(regex);
        Pattern pNoRet = Pattern.compile(regexNoRet);

        for (String line : sinkData){
            Matcher m = p.matcher(line);
            if (m.find()){
                createMethod(m);
            } else {
              Matcher mNoRet = pNoRet.matcher(line);
                if (mNoRet.find()) {
                    createMethod(mNoRet);
                } else
                    logger.warn(String.format("Sink line does not match: %s", line));
            }
        }

        for (String line : additionSourceData){
            Matcher m = p.matcher(line);
            if (m.find()){
                createMethod(m);
            } else {
                Matcher mNoRet = pNoRet.matcher(line);
                if (mNoRet.find()) {
                    createMethod(mNoRet);
                } else
                    logger.warn(String.format("Source line does not match: %s", line));
            }
        }

        for (AndroidMethod am : methods.values()){
            MethodSourceSinkDefinition singleMethod = new MethodSourceSinkDefinition(am);
            if (am.getSourceSinkType().isSource())
                sourceList.add(singleMethod);
            else if (am.getSourceSinkType().isSink())
                sinkList.add(singleMethod);
        }
    }

    private AndroidMethod createMethod(Matcher m) {
        AndroidMethod am = parseMethod(m, true);
        AndroidMethod oldMethod = methods.get(am.getSignature());
        if (oldMethod != null) {
            oldMethod.setSourceSinkType(oldMethod.getSourceSinkType().addType(am.getSourceSinkType()));
            return oldMethod;
        } else {
            methods.put(am.getSignature(), am);
            return am;
        }
    }

    private AndroidMethod parseMethod(Matcher m, boolean hasReturnType) {
        assert (m.group(1) != null && m.group(2) != null && m.group(3) != null && m.group(4) != null);
        AndroidMethod singleMethod;
        int groupIdx = 1;

        // class name
        String className = m.group(groupIdx++).trim();

        String returnType = "";
        if (hasReturnType) {
            // return type
            returnType = m.group(groupIdx++).trim();
        }

        // method name
        String methodName = m.group(groupIdx++).trim();

        // method parameter
        List<String> methodParameters = new ArrayList<String>();
        String params = m.group(groupIdx++).trim();
        if (!params.isEmpty())
            for (String parameter : params.split(","))
                methodParameters.add(parameter.trim());

        // permissions
        String classData = "";
        String permData = "";
        Set<String> permissions = null;
        ;
        if (groupIdx < m.groupCount() && m.group(groupIdx) != null) {
            permData = m.group(groupIdx);
            if (permData.contains("->")) {
                classData = permData.replace("->", "").trim();
                permData = "";
            }
            groupIdx++;
        }
        if (!permData.isEmpty()) {
            permissions = new HashSet<String>();
            for (String permission : permData.split(" "))
                permissions.add(permission);
        }

        // create method signature
        singleMethod = new AndroidMethod(methodName, methodParameters, returnType, className, permissions);

        if (classData.isEmpty())
            if (m.group(groupIdx) != null) {
                classData = m.group(groupIdx).replace("->", "").trim();
                groupIdx++;
            }
        if (!classData.isEmpty())
            for (String target : classData.split("\\s")) {
                target = target.trim();

                // Throw away categories
                if (target.contains("|"))
                    target = target.substring(target.indexOf('|'));

                if (!target.isEmpty() && !target.startsWith("|")) {
                    if (target.equals("_SOURCE_"))
                        singleMethod.setSourceSinkType(SourceSinkType.Source);
                    else if (target.equals("_SINK_"))
                        singleMethod.setSourceSinkType(SourceSinkType.Sink);
                    else if (target.equals("_NONE_"))
                        singleMethod.setSourceSinkType(SourceSinkType.Neither);
                    else if (target.equals("_BOTH_"))
                        singleMethod.setSourceSinkType(SourceSinkType.Both);
                    else
                        throw new RuntimeException("error in target definition: " + target);
                }
            }
        return singleMethod;
    }

    @Override
    public Set<? extends ISourceSinkDefinition> getSources() {
        if (sourceList == null || sinkList == null){
            parse();
        }
        return this.sourceList;
    }

    @Override
    public Set<? extends ISourceSinkDefinition> getSinks() {
        if (sourceList == null || sinkList == null){
            parse();
        }
        return this.sinkList;
    }

    @Override
    public Set<? extends ISourceSinkDefinition> getAllMethods() {
        if (sourceList == null || sinkList == null)
            parse();
        Set<ISourceSinkDefinition> sourcesinks = new HashSet<>(sourceList.size() + sinkList.size());

        sourcesinks.addAll(sourceList);
        sourcesinks.addAll(sinkList);
        return sourcesinks;
    }
}
